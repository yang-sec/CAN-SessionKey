//SSKT protocol, ECU nodes
//Shanghao Shi, Yang Xiao
//Protocol Implemention for ACSAC2020-Session key Distribution Make Practical for CAN and CAN-FD Message Authentication

#include <mcp_can.h>
#include <SPI.h>
//#include <SHA256.h>
#include <AES.h>
#include <BLAKE2s.h>
#include <GF256.h>

/* PLEASE CHANGE TO SEE DIFFERENT SETUPS */  
// Keep it the the same with the KS setup
const uint8_t M=6; // Number of MSG IDs with the max of 5.
const uint8_t N=4; // Number of normal ECUs with the max of 5. {1,2,3,4,5} are used in the paper. 

// CHOOSE ONE AND COMMENT OUT THE OTHERS
const unsigned long EID = 
//  0x001  // ECU 0
//  0x002  // ECU 1
//  0x003  // ECU 2
  0x004  // ECU 3
//  0x005  // ECU 4
//  0x006  // ECU 5
;

// CHOOSE ONE AND COMMENT OUT THE OTHERS
const uint8_t Pre_shared_key_x[16] = {
//  0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28  // ECU 0
//  0x2c,0xeb,0x89,0x11,0x5e,0x74,0xe6,0xd8,0xf6,0x8d,0xe2,0x33,0xad,0xb7,0x7b,0x4f // ECU 1
//  0x4f,0x9d,0xae,0xca,0xe3,0x15,0xad,0xf8,0x2d,0x73,0x39,0x83,0x29,0x99,0xcb,0x3c // ECU 2
  0xc1,0x3d,0x28,0xec,0x84,0xe6,0xb7,0x49,0x9e,0xd7,0xa9,0x7e,0xdd,0x4,0x8f,0xf6  // ECU 3
//  0x5b,0x47,0x27,0xe8,0x3c,0xb,0xf1,0x36,0xee,0x93,0xb,0x35,0x76,0xed,0x6a,0x2    // ECU 4
//  0x57,0x03,0x42,0xbc,0x18,0xfb,0xb1,0xf0,0x62,0x1d,0x50,0x68,0x2a,0xc,0x4a,0x51   // ECU 5
};

// CHOOSE ONE AND COMMENT OUT THE OTHERS
const uint8_t Pre_shared_key_y[16] = {
//  0x33,0x69,0x92,0x70,0x1c,0x3a,0xad,0x5,0x75,0x5b,0x9b,0x64,0x3f,0x9b,0x72,0xbd  // ECU 0
//  0xce,0xda,0x31,0x94,0x8e,0x39,0xdd,0x10,0x4a,0xe5,0xe4,0xfb,0xcd,0x2e,0x64,0x27 // ECU 1
//  0x34,0xbb,0xf7,0x19,0x2b,0x85,0x28,0x90,0x53,0x7b,0x5f,0x6a,0x7e,0xbd,0xd6,0xfd // ECU 2
  0x96,0xd7,0xd0,0x92,0x7,0x42,0xe4,0xca,0x28,0xb6,0xac,0x59,0x60,0xab,0xa9,0xa6  // ECU 3
//  0xe,0x1,0x23,0xd2,0x1c,0x1f,0x14,0xff,0x73,0xf0,0x95,0xab,0x52,0xae,0x3,0x8b    // ECU 4
//  0x7d,0x5d,0x61,0xca,0x93,0x89,0xeb,0xa4,0x2d,0xb8,0xd,0xbc,0x8b,0x83,0x41,0xa6  // ECU 5
};
  
//Set CS pin
//const int SPI_CS_PIN = 9;
MCP_CAN CAN(9);
BLAKE2s hash;
AESTiny128 AES128;

const uint8_t auxX[6]={0xfc,0xf2,0xc3,0x8,0x13,0x75}; // Same aux x coordinate for every byte

//uint8_t epoch[8]={0};
unsigned int local_epoch = 0;
uint8_t R[16];
uint8_t Session_key[M][16];
uint8_t LaCo[N+1][16]; // Lagrange Coefficients, to pre-compute

uint8_t counter, pr_counter, kd_counter;
	
void array_assignment(uint8_t *data1, uint8_t *data2, uint8_t data_len)
{
  for(uint8_t k=0;k<data_len;k++)
  {
    data1[k]=data2[k];
  }  
}


// Precompute Lagrange Coefficients
// This part is done during CAN bus setup process, computation overhead can be significantly reduced
// Details can be found in the paper
void pre_compute()
{
//  Serial.println("Pre computed Lagrange Coefficients: ");
  for(uint8_t b = 0;b < 16;b++)
  {
    for(uint8_t i = 0;i < N;i++)
    {
      LaCo[i][b] = 0;
      for(uint8_t j = 0;j < N;j++)
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
    for(uint8_t j = 0;j < N;j++)
    {
      LaCo[N][b] = ((LaCo[N][b]+GF256_Log[auxX[j]])%0xff + GF256_Log[GF256_Inv[auxX[j]^Pre_shared_key_x[b]]])%0xff;
    }
    LaCo[N][b] = GF256_Exp[LaCo[N][b]];
  }         
}


uint8_t check_pr_hmac(unsigned long ID, uint8_t epoch[8], uint8_t R[16], uint8_t hmac[8])
{
  uint8_t tmp_hmac[8];
  
  hash.reset(Pre_shared_key_x, 16, 8);
  hash.update(&ID, sizeof(ID));
  hash.update(epoch, 8);
  hash.update(R, 16);
  hash.finalize(tmp_hmac, 8);
  
  for(int k=0;k<8;k++)
  {
    if(tmp_hmac[k]!=hmac[k])
    {
      Serial.println("P");
      return 1;
    }
  }
  return 0;
}

uint8_t recover_session_key(unsigned long canId, uint8_t epoch[8], uint8_t auxY[N][16], uint8_t MAC[8], int m)
{
  uint8_t New_MAC[8];
  int tmp;
  unsigned long MID = (m + 1)*0x100;
  
//  hash.reset();
//  hash.update(&Pre_shared_key_y[0], 16);
//  hash.update(R, 16);
//  hash.update(&MID, sizeof(MID));
//  hash.finalize(R, 16);
  AES128.setKey(&Pre_shared_key_y[0], 16);
  AES128.encryptBlock(R, R);
    
  // Polynomial recovery
  for(int b=0;b<16;b++)
  {
    // Interpolation with pre-computed Lagrange coeffs
    Session_key[m][b]=0;
    for(uint8_t i=0;i<N;i++)
    {
//      Session_key[m][b] ^= (auxY[i][b]!=0x0)? GF256_Exp[(GF256_Log[auxY[i][b]]+GF256_Log[LaCo[i][b]])%0xff] : 0x0;
      tmp = GF256_Log[auxY[i][b]]+GF256_Log[LaCo[i][b]];
      Session_key[m][b] ^= (auxY[i][b]!=0x0)? GF256_Exp[(tmp<=0xff)?tmp:(tmp-0xff)] : 0x0;
    }
//    Session_key[m][b] ^= (Pre_shared_key_y[b]!=Rm[m][b])? GF256_Exp[(GF256_Log[Pre_shared_key_y[b]^Rm[m][b]]+GF256_Log[LaCo[N][b]])%0xff] : 0x0;
    tmp = GF256_Log[Pre_shared_key_y[b]^R[b]]+GF256_Log[LaCo[N][b]];
    Session_key[m][b] ^= (Pre_shared_key_y[b]!=R[b])? GF256_Exp[(tmp<=0xff)?tmp:(tmp-0xff)] : 0x0;
  }

  // Check MAC. MAC of KDMSG: hash(session key|mid|epoch)
  hash.reset(Session_key[m], 16, 8);
  hash.update(&canId, sizeof(canId));
  hash.update(epoch, 8);
  hash.finalize(New_MAC, 8);
  for(uint8_t b=0;b<8;b++)
  {
    if(New_MAC[b]!=MAC[b])
    {
      Serial.println("K");
      return 1;
    }
  }
  return 0;
}

// Send CO_MSG to KS
void send_back_message(unsigned long ID, uint8_t epoch[8])
{
  uint8_t new_hmac[8];
  hash.reset(Pre_shared_key_y, 16, 8);
//  hash.update(Pre_shared_key_y, 16);
  hash.update(&ID, sizeof(ID));
  hash.update(epoch, 8); 
  for(int m=0;m<M;m++)
  {
    hash.update(Session_key[m], 16);
  }
  hash.finalize(new_hmac, 8);
  
  CAN.sendMsgBuf(ID, 0, 8, epoch, true);
  CAN.sendMsgBuf(ID, 0, 8, new_hmac, true);

}

void display_session_key()
{
  Serial.println();
  for(int m=0;m<M;m++)
  {
//    Serial.print("k");
//    Serial.print(m+1);
//    Serial.print(":\t");
    for(uint8_t b=0;b<16;b++)
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
  CAN.init_Mask(0, 1, 0xfffff000);
  CAN.init_Mask(1, 1, 0xfffff000);
  CAN.init_Filt(0, 1, EID*0x100000);   // For PR_MSG
  CAN.init_Filt(1, 1, 0x10000000);  // For KD_MSGs
  Serial.println();

//  epoch[7] = 1;
  local_epoch = 1;
  pre_compute();
  pr_counter = 0;
  kd_counter = 0;
  counter=0;  
}




void loop()
{
  uint8_t auxY[N][16]; // Works like a static variable
  uint8_t len;
  uint8_t buf[8];
  unsigned long canId;
  uint8_t epoch[8];
  uint8_t hmac[8];
//  static uint8_t curr_m;

  if (CAN_MSGAVAIL == CAN.checkReceive()) // check if data coming
  {
    CAN.readMsgBufID(&canId, &len, buf);    // read data
//    Serial.println("  ");
//    canId = CAN.getCanId();
//    Serial.print("------- Get data from ID: 0x");
//    Serial.println(canId, HEX);
//    for (int i = 0; i < len; i++) // print the data
//    { 
//        Serial.print(buf[i],HEX);
//        Serial.print(" ");
//    }
//    Serial.println();

    if(pr_counter < 4 && canId < 0x10000000) // PR_MSG
    {
      switch(canId - EID*0x100000)
      {
        case 0:
          array_assignment(epoch, buf, 8);
//          if(epoch[7]!=epoch)
          if(epoch[7] != local_epoch%0x10)
          {
            Serial.println("PE");
            counter = 0;
            pr_counter = 0;
            kd_counter = 0;
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
          break;
      }
      pr_counter++;
      if(pr_counter == 4)
      {
//        check_pr_hmac(EID*0x100000, R, hmac);
        check_pr_hmac(EID*0x100000, epoch, R, hmac);
        counter += 4;
      }
    }
    else if(canId >= 0x10000000) // KD_MSG
    {
      if(canId%0x100 == 0)
      {
        array_assignment(epoch,buf,8);
        if(epoch[7] != local_epoch%0x10)
        {
          Serial.println("KE");
          counter = 0;
          pr_counter = 0;
          kd_counter = 0;
          return;
        }
//        curr_m = (canId-0x10000100)/0x100;
      }
      else if(canId%0x100 >= 1 && canId%0x100 <= 2*N) // N aux points
      {
        array_assignment(&auxY[(canId%0x100-1)/2][8*((canId%0x100-1)%2)], buf, 8);
      }
      else if(canId%0x100 == 2*N+1)
      {
        array_assignment(hmac, buf, 8);
      }
      
      kd_counter++;
      if(kd_counter == 2+2*N)
      {
        Serial.println((canId-0x10000100)/0x100);
//        recover_session_key(canId&0xffffff00, auxY, hmac, (canId-0x10000100)/0x100);
        recover_session_key(canId&0xffffff00, epoch, auxY, hmac, (canId-0x10000100)/0x100);
        counter += 2*N+2;
        kd_counter = 0;
      }
    }

//    Serial.print("counter = ");
//    Serial.print(counter);
    
    if(counter == 4+(2+2*N)*M)
    {
      for(uint8_t repeat=0;repeat<5;repeat++)
      {	
        delayMicroseconds((EID-1)*500);
  			send_back_message(0x200 + EID, epoch);
      }
      kd_counter = 0;
      pr_counter = 0;
      counter = 0;
      display_session_key();
    }
  }
}

//END FILE
