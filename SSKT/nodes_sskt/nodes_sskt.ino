//SKDC protocol, ECU nodes
//Shanghao Shi
//Protocol Implemention for ACSAC2020-Session key Distribution Make Practical for CAN and CAN-FD Message Authentication

#include <mcp_can.h>
#include <SPI.h>
#include <SHA256.h>
#include <GF256.h>

/* PLEASE CHANGE TO SEE DIFFERENT SETUPS */  
// Keep it the the same with the KS setup
const int M=5; // Number of MSG IDs. Please fix M=1.
const int N=2; // Number of normal ECUs with the max of 6. {1,2,3,4,5,6} are used in the paper. 

// CHOOSE ONE AND COMMENT OUT THE OTHERS
unsigned long EID= 
  0x001  // ECU 0
//  0x002  // ECU 1
//  0x003  // ECU 2
//  0x004  // ECU 3
//  0x005  // ECU 4
//  0x006  // ECU 5
;

// CHOOSE ONE AND COMMENT OUT THE OTHERS
uint8_t Pre_shared_key_x[16]={
  0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28  // ECU 0
//  0x2c,0xeb,0x89,0x11,0x5e,0x74,0xe6,0xd8,0xf6,0x8d,0xe2,0x33,0xad,0xb7,0x7b,0x4f // ECU 1
//  0x4f,0x9d,0xae,0xca,0xe3,0x15,0xad,0xf8,0x2d,0x73,0x39,0x83,0x29,0x99,0xcb,0x3c // ECU 2
//  0xc1,0x3d,0x28,0xec,0x84,0xe6,0xb7,0x49,0x9e,0xd7,0xa9,0x7e,0xdd,0x4,0x8f,0xf6  // ECU 3
//  0x5b,0x47,0x27,0xe8,0x3c,0xb,0xf1,0x36,0xee,0x93,0xb,0x35,0x76,0xed,0x6a,0x2    // ECU 4
};

// CHOOSE ONE AND COMMENT OUT THE OTHERS
uint8_t Pre_shared_key_y[16]={
  0x33,0x69,0x92,0x70,0x1c,0x3a,0xad,0x5,0x75,0x5b,0x9b,0x64,0x3f,0x9b,0x72,0xbd  // ECU 0
//  0xce,0xda,0x31,0x94,0x8e,0x39,0xdd,0x10,0x4a,0xe5,0xe4,0xfb,0xcd,0x2e,0x64,0x27 // ECU 1
//  0x34,0xbb,0xf7,0x19,0x2b,0x85,0x28,0x90,0x53,0x7b,0x5f,0x6a,0x7e,0xbd,0xd6,0xfd // ECU 2
//  0x96,0xd7,0xd0,0x92,0x7,0x42,0xe4,0xca,0x28,0xb6,0xac,0x59,0x60,0xab,0xa9,0xa6  // ECU 3
//  0xe,0x0,0x23,0xd2,0x1c,0x1f,0x14,0xff,0x73,0xf0,0x95,0xab,0x52,0xae,0x3,0x8b    // ECU 4
};
  
//Set CS pin
const int SPI_CS_PIN = 9;
MCP_CAN CAN(SPI_CS_PIN);
SHA256 hash;

uint8_t auxX_All[5]={0xfc,0xf2,0xc3,0x07,0x13}; // Same aux x coordinate for every byte
uint8_t auxX[N];

uint8_t epoch[8]={0};
uint8_t R[16], Rm[16];
uint8_t Session_key[M][16];
uint8_t LaCo[N+1][16]; // Lagrange Coefficients, to pre-compute


uint8_t counter, pr_counter, kd_counter;
	
void array_assignment(uint8_t *array_1, uint8_t *array_2, uint8_t array_len)
{
  for(int i=0;i<array_len;i++)
  {
    array_1[i]=array_2[i];
  }
}


// Precompute Lagrange Coefficients
// This part is done during CAN bus setup process, computation overhead can be significantly reduced
// Details can be found in the paper
void pre_compute()
{
//  Serial.println("Pre computed Lagrange Coefficients: ");
  for(int b = 0;b < 16;b++)
  {
    for(int i = 0;i < N;i++)
    {
      LaCo[i][b] = 0;
      for(int j = 0;j < N;j++)
      {
        if(j != i)
        {
          LaCo[i][b] = ((LaCo[i][b]+GF256_Log[auxX[j]])%0xff + GF256_Log[GF256_Inv[auxX[j]^auxX[i]]])%0xff;
        }
      }
      LaCo[i][b] = ((LaCo[i][b]+GF256_Log[Pre_shared_key_x[b]])%0xff + GF256_Log[GF256_Inv[Pre_shared_key_x[b]^auxX[i]]])%0xff;
      LaCo[i][b] = GF256_Exp[LaCo[i][b]];
    }

    LaCo[N][b] = 0;
    for(int j = 0;j < N;j++)
    {
      LaCo[N][b] = ((LaCo[N][b]+GF256_Log[auxX[j]])%0xff + GF256_Log[GF256_Inv[auxX[j]^Pre_shared_key_x[b]]])%0xff;
    }
    LaCo[N][b] = GF256_Exp[LaCo[N][b]];
  }         
}


uint8_t check_pr_hmac(unsigned long ID, uint8_t R[16], uint8_t hmac[8])
{
  uint8_t tmp_hmac[8];
  hash.resetHMAC(Pre_shared_key_x, 16);
  hash.update(&ID, sizeof(ID));
  hash.update(epoch, 8);
  hash.update(R, 16);
  hash.finalizeHMAC(Pre_shared_key_x, 16, tmp_hmac, 8);
  for(int k=0;k<8;k++)
  {
    if(tmp_hmac[k]!=hmac[k])
    {
      Serial.println("PR HMAC?");
      return 1;
    }
  }
  return 0;
}

uint8_t recover_session_key(unsigned long canId, uint8_t auxY[N][16], uint8_t MAC[8])
{
  uint8_t New_MAC[8];
  unsigned long MID = canId - 0x10000000;
//  double t1;

//  t1 = micros();
  
  hash.reset();
  hash.update(R, 16);
  hash.update(&MID, sizeof(MID));
  hash.finalize(Rm, 16); // R for MID m
  
  for(int b=0;b<16;b++)
  {
    // Interpolation with pre-computed Lagrange coeffs
    Session_key[MID-1][b]=0;
    for(int i=0;i<N;i++)
    {
      Session_key[MID-1][b] ^= GF256_Exp[(GF256_Log[auxY[i][b]]+GF256_Log[LaCo[i][b]])%0xff];
    }
    Session_key[MID-1][b] ^= GF256_Exp[(GF256_Log[Pre_shared_key_y[b]^Rm[b]]+GF256_Log[LaCo[N][b]])%0xff];
  }

  // Check MAC. MAC of KDMSG: hash(session key|mid|epoch)
  hash.resetHMAC(Session_key[MID-1], 16);
  hash.update(&canId, sizeof(canId));
  hash.update(epoch, 8);
  hash.finalizeHMAC(Session_key[MID-1], 16, New_MAC, 8);
  for(int b=0;b<8;b++)
  {
    if(New_MAC[b]!=MAC[b])
    {
      Serial.println("KD HMAC?");
      return 1;
    }
  }
//  Serial.println(micros()-t1);
  return 0;
}

// Send CO_MSG to KS
void send_back_message(unsigned long ID)
{
  uint8_t new_hmac[8];
  hash.resetHMAC(Pre_shared_key_y, 16);
  hash.update(&ID, sizeof(ID));
  hash.update(epoch, 8);
      
  for(int m=0;m<M;m++)
  {
    hash.update(Session_key[m], 16);
  }
  hash.finalizeHMAC(Pre_shared_key_y, 16, new_hmac, 8);
  CAN.sendMsgBuf(ID, 0, 8, epoch, true);
  CAN.sendMsgBuf(ID, 0, 8, new_hmac, true);

}

void display_session_key()
{
  for(int m=0;m<M;m++)
  {
    Serial.print("MSG 0x");
    Serial.print(m+1);
    Serial.print(":\t");
    for(int b=0;b<16;b++)
    {
      Serial.print(Session_key[m][b],HEX);
      Serial.print(" ");
    }
    Serial.println();
  }
}

void setup() 
{
  Serial.begin(115200);
  while (CAN_OK != CAN.begin(CAN_500KBPS)) // init can bus
  {            
//      Serial.println("CAN BUS Shield init fail");
//      Serial.println("Init CAN BUS Shield again");
      delay(100);
  }
  
	// Initilize Masks and Filters
	// Different ECU nodes need different Masks and Filters initilization to receive different message
  CAN.init_Mask(0, 1, 0xffffffff);
  CAN.init_Mask(1, 1, 0xffffffff);
  CAN.init_Filt(0, 1, EID);   // For PR_MSG
  CAN.init_Filt(1, 1, 0x10000001);  // For KD_MSG of MID 1
  CAN.init_Filt(2, 1, 0x10000002);  // For KD_MSG of MID 2
  CAN.init_Filt(3, 1, 0x10000003);  // For KD_MSG of MID 3
  CAN.init_Filt(4, 1, 0x10000004);  // For KD_MSG of MID 4
  CAN.init_Filt(5, 1, 0x10000005);  // For KD_MSG of MID 5
//  Serial.println("CAN BUS Shield init ok!");
  Serial.println();

  for(int n=0;n<N;n++)
  {
    auxX[n] = auxX_All[n];
  }
  epoch[7]=1;
  pre_compute();
  pr_counter = 0;
  kd_counter = 0;
  counter=0;  
}


//uint8_t auxY[N][16];

void loop()
{
  uint8_t auxY[N][16]; // Works like a static variable
  uint8_t len;
  uint8_t buf[8];
  unsigned long canId, MID;
  uint8_t tmp_epoch[8];
  uint8_t hmac[8];
  uint8_t flag;

  flag = 0;
  if (CAN_MSGAVAIL == CAN.checkReceive()) // check if data coming
  {
    CAN.readMsgBufID(&canId, &len, buf);    // read data
//    canId = CAN.getCanId();
//    Serial.print("------- Get data from ID: 0x");
//    Serial.println(canId, HEX);
//    for (int i = 0; i < len; i++) // print the data
//    { 
//        Serial.print(buf[i],HEX);
//        Serial.print("\t");
//    }
//    Serial.println();

    if(canId == EID) // PR_MSG
    {
      switch(pr_counter)
      {
        case 0:
          array_assignment(tmp_epoch,buf,8);
          if(tmp_epoch[7]!=epoch[7])
          {
            Serial.println("PR Epoch?");
            return;
          }
          break;
        case 1:
          array_assignment(R, buf, 8);
          break;
        case 2:
          array_assignment(&R[8], buf, 8);
          break;
        case 3:
          array_assignment(hmac, buf, 8);
          flag = check_pr_hmac(canId, R, hmac);
          break;
      }
      pr_counter++;
    }
    else if(canId >= 0x10000001 && canId <= 0x10000fff) // KD_MSG
    {
      MID = canId - 0x10000000;
      if(kd_counter==0)
      {
        array_assignment(tmp_epoch,buf,8);
        if(tmp_epoch[7]!=epoch[7])
        {
          Serial.println("KD Epoch?");
          return;
        }
        kd_counter++;
      }
      else if(kd_counter >= 1 && kd_counter <= 2*N) // N aux points
      {
        switch(kd_counter%2)
        {
          case 1:
            array_assignment(&auxY[(kd_counter-1)/2][0], buf, 8);
            break;
          case 0:
            array_assignment(&auxY[(kd_counter-1)/2][8], buf, 8);
            break;
        }
        kd_counter++;
      }
      else if(kd_counter == 2*N+1)
      {
        array_assignment(hmac, buf, 8);
        flag = recover_session_key(canId, auxY, hmac);
        kd_counter = 0;
      }
    }
    else
    {
      Serial.println("Unknown ID.");
      return;
    }

//    Serial.print("counter = ");
//    Serial.print(counter);
    counter++;
    
    if(counter == 4+(2+2*N)*M)
    {
      for(int repeat=0;repeat<5;repeat++)
      {	
  			send_back_message(0x200 + EID);
//  			delay(3);
      }
      kd_counter = 0;
      pr_counter = 0;
      counter = 0;
      display_session_key();
    }
  }
}

//END FILE
