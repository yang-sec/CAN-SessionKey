//SKDC protocol, ECU nodes
//Shanghao Shi
//Protocol Implemention for ACSAC2020-Session key Distribution Make Practical for CAN and CAN-FD Message Authentication

#include <SPI.h>
#include "mcp_can.h"
#include <SHA256.h>
#include <GF256.h>

/* PLEASE CHANGE TO SEE DIFFERENT SETUPS */  
// Keep it the the same with the KS setup
const int M=1; // Number of MSG IDs. Please fix M=1.
const int N=2; // Number of normal ECUs with the max of 6. {2,3,4,5,6} are used in the paper. 

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
uint8_t Pre_shared_key_x[16]=
  0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28  // ECU 0
//  0x2c,0xeb,0x89,0x11,0x5e,0x74,0xe6,0xd8,0xf6,0x8d,0xe2,0x33,0xad,0xb7,0x7b,0x4f // ECU 1
//  0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28  // ECU 2
//  0x2c,0xeb,0x89,0x11,0x5e,0x74,0xe6,0xd8,0xf6,0x8d,0xe2,0x33,0xad,0xb7,0x7b,0x4f // ECU 3
//  0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28  // ECU 4
//  0x2c,0xeb,0x89,0x11,0x5e,0x74,0xe6,0xd8,0xf6,0x8d,0xe2,0x33,0xad,0xb7,0x7b,0x4f // ECU 5
};

// CHOOSE ONE AND COMMENT OUT THE OTHERS
uint8_t Pre_shared_key_y[16]=
  0x33,0x69,0x92,0x70,0x1c,0x3a,0xad,0x5,0x75,0x5b,0x9b,0x64,0x3f,0x9b,0x72,0xbd  // ECU 0
//  0xce,0xda,0x31,0x94,0x8e,0x39,0xdd,0x10,0x4a,0xe5,0xe4,0xfb,0xcd,0x2e,0x64,0x27 // ECU 1
//  0x33,0x69,0x92,0x70,0x1c,0x3a,0xad,0x5,0x75,0x5b,0x9b,0x64,0x3f,0x9b,0x72,0xbd  // ECU 2
//  0xce,0xda,0x31,0x94,0x8e,0x39,0xdd,0x10,0x4a,0xe5,0xe4,0xfb,0xcd,0x2e,0x64,0x27 // ECU 3
//  0x33,0x69,0x92,0x70,0x1c,0x3a,0xad,0x5,0x75,0x5b,0x9b,0x64,0x3f,0x9b,0x72,0xbd  // ECU 4
//  0xce,0xda,0x31,0x94,0x8e,0x39,0xdd,0x10,0x4a,0xe5,0xe4,0xfb,0xcd,0x2e,0x64,0x27 // ECU 5
};
  
//Set CS pin
const int SPI_CS_PIN = 9;
MCP_CAN CAN(SPI_CS_PIN);
SHA256 hash;


uint8_t ListTT[5]={0xFC,0xF1,0xCD,0x07,0x13};
uint8_t List[N-1];

uint8_t epoch[8]={0,0,0,0,0,0,0,0};
uint8_t R[16];
uint8_t Session_key[M][16];
uint8_t Pre_computed_list[N][16];

int counter, pr_counter, kd_counter;
    
	
void array_assignment(uint8_t *array_1, uint8_t *array_2, uint8_t array_len)
{
  for(int i=0;i<array_len;i++)
  {
    array_1[i]=array_2[i];
  }
}


//Precompute process
//This part is done during CAN bus setup process, computation overhead can be significantly reduced
//Details can be found in the paper
void pre_compute()
{
  uint8_t New_list[N];
  array_assignment(New_list, List, N-1);
  for(int j=0;j<N;j++)
  {
    Serial.println("Pre_computed_list:");
    for(int k=0;k<16;k++)
    {
      New_list[N-1]=Pre_shared_key_x[k];
      Pre_computed_list[j][k]=0;
      for(int l=0;l<N;l++)
      {
        if(l != j)
        {
          Pre_computed_list[j][k]=((Pre_computed_list[j][k]+GF256_Log[New_list[l]])%0xff+GF256_Log[GF256_Inv[New_list[j]^New_list[l]]])%0xff;//delete 0x01
        }
      }
      Pre_computed_list[j][k]=GF256_Exp[Pre_computed_list[j][k]];
      Serial.print(Pre_computed_list[j][k],HEX);
      Serial.print("\t");
    }  
    Serial.println();    
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
      Serial.println("PR_MSG HMAC does not match");
      return 1;
    } 
  }
  return 0;
}


uint8_t recover_session_key(
  uint8_t Pre_computed_list[N][16], 
  uint8_t Pre_shared_secret_y[16], 
  uint8_t R[16], 
  uint8_t points[N-1][16], 
  unsigned long canID, 
  uint8_t epoch[8],
  uint8_t MAC[8],
  uint8_t Session_key[16])
{
  uint8_t New_MAC[8];
  
  for(int i=0;i<16;i++)
  {
    // Interpolation with pre-computed Lagrange coeffs
    Session_key[i]=0;
    for(int j=0;j<N;j++)
    {
      if(j!=(N-1))
      {
        Session_key[i]=Session_key[i]^GF256_Exp[(GF256_Log[points[j][i]]+GF256_Log[Pre_computed_list[j][i]])%0xff];
      }
      else
      {
        Session_key[i]=Session_key[i]^GF256_Exp[(GF256_Log[Pre_shared_secret_y[i]^R[i]]+GF256_Log[Pre_computed_list[j][i]])%0xff];
      }
    }
  }

  // Check MAC. MAC of KDMSG: hash(session key|mid|epoch)
  hash.reset();
  hash.update(Session_key, 16);
  hash.update(&canID, sizeof(canID));
  hash.update(epoch, 8);
  hash.finalize(New_MAC,8);
  for(int b=0;b<8;b++)
  {
    if(New_MAC[b]!=MAC[b])
    {
      Serial.println("KDMSG MAC not check");
      return 1;
    }
  }
  return 0;
}

// Send CO_MSG to KS
void send_back_message(uint8_t flag)
{
  uint8_t new_hmac[8];
  unsigned long ID = 0x200 + EID; // In binary: 010||EID
  hash.resetHMAC(Pre_shared_key, 16);
  hash.update(&ID, sizeof(ID));
  hash.update(epoch, 8);
      
  if(flag==0)
  {
    for(int m=0;m<M;m++)
    {
      hash.update(Session_key[m], 16);
    }
    hash.finalizeHMAC(Pre_shared_key, 16, new_hmac, 8);

//      Serial.print("------- send COMSG with ID ");
//      Serial.print(ID,HEX);
//      Serial.println(" -------");

    CAN.sendMsgBuf(ID, 0, 8, epoch);
//      Serial.print("Epoch:\t");
//      for (int i = 0; i < 8; i++) { // print the data
//            Serial.print(epoch[i],HEX);
//            Serial.print("\t");
//      }
//      Serial.println();
    
    CAN.sendMsgBuf(ID, 0, 8, new_hmac);
//      Serial.print("HMAC:\t");
//      for (int i = 0; i < 8; i++) { // print the data
//            Serial.print(new_hmac[i],HEX);
//            Serial.print("\t");
//      }
//      Serial.println();
  }
  else
  { 
    Serial.println("[KDMSG MAC does not check]");
    hash.finalizeHMAC(Pre_shared_key, 16, new_hmac, 8);
    CAN.sendMsgBuf(ID, 0, 8, epoch);
    CAN.sendMsgBuf(ID, 0, 8, new_hmac);      
  }
}

void display_session_key()
{
  Serial.println();
  Serial.println("------- get session key -------");

  for(int m=0;m<M;m++)
  {
    Serial.print("MSG 0x");
    Serial.print(m+1);
    Serial.print(":\t");
    for(int k=0;k<16;k++)
    {
      Serial.print(Session_key[m][k],HEX);
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
      Serial.println("CAN BUS Shield init fail");
      Serial.println("Init CAN BUS Shield again");
      delay(100);
  }
  
	// Initilize Masks and Filters
	// Different ECU nodes need different Masks and Filters initilization to receive different message
  CAN.init_Mask(0, 1, 0x1fffffff);
  CAN.init_Mask(1, 1, 0x1fffffff);
  CAN.init_Filt(0, 0, 0x200+MID);   // For PR_MSG
  CAN.init_Filt(1, 1, 0x00000001);  // For KD_MSG of MID 1
  CAN.init_Filt(2, 1, 0x00000002);  // For KD_MSG of MID 2
  Serial.println("CAN BUS Shield init ok!");
  Serial.println();

  for(int n=0;n<N-1;n++)
  {
    List[n] = ListTT[n];
  }
  epoch[7]=1;
  pre_compute();
  counter=0;  
}


uint8_t len;
uint8_t buf[8];
unsigned long canId;
uint8_t tmp_epoch[8];
uint8_t aux_points[N][16];
uint8_t pr_hmac[8];
uint8_t kd_hmac[8];
uint8_t flag;
unsigned long MID;

void loop()
{
    flag = 0;
    if (CAN_MSGAVAIL == CAN.checkReceive()) // check if data coming
    {
      CAN.readMsgBuf(&len, buf);    // read data
      canId = CAN.getCanId();
//      Serial.println("-----------------------------");
//      Serial.print("------- Get data from ID: 0x");
//      Serial.println(canId, HEX);
//      for (int i = 0; i < len; i++) // print the data
//      { 
//          Serial.print(buf[i],HEX);
//          Serial.print("\t");
//      }
//      Serial.println();

    if(canID == EID) // PR_MSG
    {
      switch(pr_counter)
      {
        case 0:
          array_assignment(tmp_epoch,buf,8);
          if(tmp_epoch[7]!=epoch[7])
          {
            Serial.println("PR_MSG epoch outdated.");
            pr_counter--;
          }
          break;
        case 1:
          array_assignment(R, buf, 8);
          break;
        case 2:
          array_assignment(&R[8], buf, 8);
          break;
        case 3:
          array_assignment(pr_hmac, buf, 8);
          flag = check_pr_hmac(canId, R[0], pr_hmac);
          break;
      }
      pr_counter++;
    }
    else if(canID >= 0x10000001 && canID <= 0x10000fff) // KD_MSG
    {
      MID = canId - 0x10000000;
      if(kd_counter==0)
      {
        array_assignment(tmp_epoch,buf,8);
        if(tmp_epoch[7]!=epoch[7])
        {
          Serial.println("KD_MSG epoch outdated.");
          kd_counter--;
        }
      }
      else if(kd_counter >= 1 && kd_counter <= 2*N) // N aux points
      {
        switch(kd_counter%2)
        {
          case 1:
            array_assignment(aux_points[kd_counter-1], buf, 8);
            break;
          case 2:
            array_assignment(&aux_points[kd_counter-1][8], buf, 8);
            break;
        }
      }
      else if(kd_counter == 2*N+1)
      {
        array_assignment(kd_hmac, buf, 8);
        flag = recover_session_key(Pre_computed_list[0], Pre_shared_key_y, R[0], points, canId, epoch, MAC, Session_key[0]);
      }
      kd_counter++;
    }
    else
    {
      Serial.println("CAN ID unsupported.");
      return;
    }

    counter++;
//    Serial.print("counter = ");
//    Serial.println(counter);
    
    if(counter==4+2+2*N)
    {
      for(int repeat=0;repeat<5;repeat++)
      {	
  			send_message_back(flag);
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
