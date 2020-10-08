// SKDC protocol, ECU node
// Shanghao Shi, Yang Xiao
// Protocol Implemention for ACSAC2020-Session key Distribution Make Practical for CAN and CAN-FD Message Authentication

#include "mcp_can.h"
#include <AES.h>
//#include <SHA256.h>
#include <BLAKE2s.h>

const int M=1; // Number of MSG IDs.

// CHOOSE ONE AND COMMENT OUT THE OTHERS
unsigned long EID= 
//  0x001  // ECU 0
//  0x002  // ECU 1
//  0x003  // ECU 2
//  0x004  // ECU 3
//  0x005  // ECU 4
  0x006  // ECU 5
;

// CHOOSE ONE AND COMMENT OUT THE OTHERS
uint8_t Pre_shared_key[16]={
//  0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28  // ECU 0
//  0x2c,0xeb,0x89,0x11,0x5e,0x74,0xe6,0xd8,0xf6,0x8d,0xe2,0x33,0xad,0xb7,0x7b,0x4f // ECU 1
//  0x4f,0x9d,0xae,0xca,0xe3,0x15,0xad,0xf8,0x2d,0x73,0x39,0x83,0x29,0x99,0xcb,0x3c // ECU 2
//  0xc1,0x3d,0x28,0xec,0x84,0xe6,0xb7,0x49,0x9e,0xd7,0xa9,0x7e,0xdd,0x4,0x8f,0xf6  // ECU 3
//  0x5b,0x47,0x27,0xe8,0x3c,0xb,0xf1,0x36,0xee,0x93,0xb,0x35,0x76,0xed,0x6a,0x2    // ECU 4
  0x57,0x03,0x42,0xbc,0x18,0xfb,0xb1,0xf0,0x62,0x1d,0x50,0x68,0x2a,0xc,0x4a,0x51 // ECU 5
}; 

//set CS pin
const int SPI_CS_PIN = 9;
MCP_CAN CAN(SPI_CS_PIN);
AESSmall128 AES128;
BLAKE2s hash;

uint8_t Session_key[M][16];
uint8_t epoch[8]={0,0,0,0,0,0,0,0};

int kd_counter;

void array_assignment(uint8_t *data1,uint8_t *data2, uint8_t data_len)
{
  for(int k=0;k<data_len;k++)
  {
    data1[k]=data2[k];
  }  
}

uint8_t recover_session_key(unsigned long ID, uint8_t encrypted_key[16], uint8_t hmac[8], int m)
{
  uint8_t tmp_hmac[8];
  
	AES128.setKey(Pre_shared_key, 16);
	AES128.decryptBlock(Session_key[m], encrypted_key);

  hash.reset(Pre_shared_key, 16, 8);
  hash.update(&ID, sizeof(ID));
  hash.update(epoch, 8);
  hash.update(Session_key[m], 16);
  hash.finalize(tmp_hmac, 8);
  for(int k=0;k<8;k++)
  {
    if(tmp_hmac[k]!=hmac[k])
    {
      Serial.println("KD_MSG HMAC not match.");
      return 1;
    } 
  }
  return 0; 
}


// Send CO_MSG to KS
void send_back_message(unsigned long ID)
{
	uint8_t new_hmac[8];
//  hash.resetHMAC(Pre_shared_key, 16);
  hash.reset(Pre_shared_key, 16, 8);
  hash.update(&ID, sizeof(ID));
  hash.update(epoch, 8);

	for(int m=0;m<M;m++)
	{
		hash.update(Session_key[m], 16);
	}
//	hash.finalizeHMAC(Pre_shared_key, 16, new_hmac, 8);
  hash.finalize(new_hmac, 8);
 
	CAN.sendMsgBuf(ID, 0, 8, epoch);
	CAN.sendMsgBuf(ID, 0, 8, new_hmac);
}


void display_session_key()
{
  Serial.println();
  Serial.println("------- get session key -------");

  for(int m=0;m<M;m++)
  {
    Serial.print("sk");
    Serial.print(m+1);
    Serial.print(":\t");
    for(int k=0;k<16;k++)
    {
      Serial.print(Session_key[m][k],HEX);
      Serial.print(" ");
    }
    Serial.println();
  }
  Serial.println();

}

void setup() 
{
  Serial.begin(115200);
  while (CAN_OK != CAN.begin(CAN_500KBPS)) // init can bus
  {
//    Serial.println("CAN BUS Shield init fail");
//    Serial.println("Init CAN BUS Shield again");
    delay(100);
  }
	epoch[7]=1;
 
	// Initilize Masks and Filters 
  // The following are straightforward. Can be done with fewer filters.
  CAN.init_Mask(0, 1, 0xffff0000);
  CAN.init_Mask(1, 1, 0xffff0000);
  CAN.init_Filt(0, 1, (0x100+EID)*0x100000); // For KD_MSGs
  Serial.println("CAN BUS Shield init ok!");
  Serial.print("SKDC Node. EID = 0x");
  Serial.println(EID, HEX);
  epoch[7]=1;
  kd_counter = 0;
}



  
void loop() 
{
  uint8_t len;
  uint8_t buf[8];
  unsigned long canId;
  uint8_t tmp_epoch[8];
  uint8_t tmp_encrypted_key[16];
  uint8_t hmac[8];
  uint8_t flag;
  unsigned long MID;
  flag = 0;
  
  if (CAN_MSGAVAIL == CAN.checkReceive())  // check if data coming
  {
    CAN.readMsgBufID(&canId, &len, buf);    // read data

//    canId = CAN.getCanId();
//    Serial.println("-----------------------------");
//    Serial.print("get data with MSG ID: 0x");
//    Serial.println(canId, HEX);
//    for (int i = 0; i < len; i++) { // print the data
//        Serial.print(buf[i],HEX);
//        Serial.print("\t");
//    }
//    Serial.println();

    if(canId >= (0x100+EID)*0x100000 && canId <= (0x100+EID)*0x100000+0xffff) // PR_MSG
    {
      switch(canId&0x000000ff)
      {
        case 0:
          array_assignment(tmp_epoch, buf, 8);
          if(tmp_epoch[7]!=epoch[7])
          {
            Serial.println("KD_MSG outdated.");
            kd_counter = 0;
            return;
          }
          break;
        case 1:
          array_assignment(tmp_encrypted_key, buf, 8);
          break;
        case 2:
          array_assignment(&tmp_encrypted_key[8], buf, 8);
          break;
        case 3:
          array_assignment(hmac, buf, 8);
          break;
      }
      
      kd_counter++;
      if(kd_counter > 0 && kd_counter%4 == 0)
      {
        Serial.println((canId&0x000fff00)/0x100 - 1);
        recover_session_key(canId&0xffffff00, tmp_encrypted_key, hmac, (canId&0x000fff00)/0x100 - 1);
      }
    }
    
//    switch(kd_counter%4)
//    {
//      case 0:
//        array_assignment(tmp_epoch,buf,8);
//        if(tmp_epoch[7]!=epoch[7])
//        {
//          Serial.println("KD_MSG outdated.");
//          return;
//        }
//        break;
//      case 1:
//        array_assignment(tmp_encrypted_key, buf, 8);
//        break;
//      case 2:
//        array_assignment(&tmp_encrypted_key[8], buf, 8);
//        break;
//      case 3:
//        array_assignment(hmac,buf,8);
//        recover_session_key(canId, tmp_encrypted_key, hmac, MID-1);
//        break;
//    }
//    kd_counter++;
    
    if(kd_counter == 4*M)
		{
      for(int repeat=0;repeat<5;repeat++)
      {
        send_back_message(0x200 + EID);
//        delay(3);
      }
      kd_counter = 0;
      display_session_key();
    }     
  }
}

//END FILE
