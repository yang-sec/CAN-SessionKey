//SKDC protocol, ECU node
//Shanghao Shi
//Protocol Implemention for ACSAC2020-Session key Distribution Make Practical for CAN and CAN-FD Message Authentication

#include "mcp_can.h"
#include <AES.h>
#include <SHA256.h>

const int M=1; // Number of MSG IDs. Please fix M = 1.

// CHOOSE ONE AND COMMENT OUT THE OTHERS
unsigned long EID= 
//  0x001  // ECU 0
//  0x002  // ECU 1
  0x003  // ECU 2
//  0x004  // ECU 3
//  0x005  // ECU 4
//  0x006  // ECU 5
;

// CHOOSE ONE AND COMMENT OUT THE OTHERS
uint8_t Pre_shared_key[16]={
//  0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28  // ECU 0
//  0x2c,0xeb,0x89,0x11,0x5e,0x74,0xe6,0xd8,0xf6,0x8d,0xe2,0x33,0xad,0xb7,0x7b,0x4f // ECU 1
  0x4f,0x9d,0xae,0xca,0xe3,0x15,0xad,0xf8,0x2d,0x73,0x39,0x83,0x29,0x99,0xcb,0x3c // ECU 2
//  0xc1,0x3d,0x28,0xec,0x84,0xe6,0xb7,0x49,0x9e,0xd7,0xa9,0x7e,0xdd,0x4,0x8f,0xf6  // ECU 3
//  0x5b,0x47,0x27,0xe8,0x3c,0xb,0xf1,0x36,0xee,0x93,0xb,0x35,0x76,0xed,0x6a,0x2    // ECU 4
//  0x1b,0x28,0xde,0x9b,0xd6,0x9c,0xb4,0x6,0x77,0xf5,0x4f,0xb7,0xd4,0x15,0x78,0x76  // ECU 5
}; 

//set CS pin
const int SPI_CS_PIN = 9;
MCP_CAN CAN(SPI_CS_PIN);
AESSmall128 AES128;
SHA256 hash;

//uint8_t counter;
uint8_t Session_key[M][16];
uint8_t epoch[8]={0,0,0,0,0,0,0,0};

int counter;

void array_assignment(uint8_t *data1,uint8_t *data2, uint8_t data_len){
  for(int k=0;k<data_len;k++){
    data1[k]=data2[k];
    }  
  }

uint8_t recover_session_key(uint8_t encrypted_key[16], int m)
{
	AES128.setKey(Pre_shared_key, 16);
	AES128.decryptBlock(Session_key[m], encrypted_key);
}

void display_session_key()
{
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
  
uint8_t check_hmac(unsigned long ID, uint8_t hmac[8], int m)
{
	uint8_t new_hmac[8];
	hash.resetHMAC(Pre_shared_key, 16);
	hash.update(&ID, sizeof(ID));
	hash.update(epoch, 8);
	hash.update(Session_key[m], 16);
	hash.finalizeHMAC(Pre_shared_key, 16, new_hmac, 8);
	for(int k=0;k<8;k++)
	{
		if(new_hmac[k]!=hmac[k])
		{
			return 1;
	  } 
	}
	return 0;
}


void send_back_message(uint8_t flag)
{
	uint8_t new_hmac[8];
  unsigned long ID = 0x2*0x100 + EID;
  hash.resetHMAC(Pre_shared_key, 16);
  hash.update(&ID, sizeof(ID));
  hash.update(epoch, 8);
      
	if(flag==0){
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
	else{ 
      Serial.println("[KDMSG MAC does not check]");
			hash.finalizeHMAC(Pre_shared_key, 16, new_hmac, 8);
			CAN.sendMsgBuf(ID, 0, 8, epoch);
//			delay(10);
			CAN.sendMsgBuf(ID, 0, 8, new_hmac);
//      delay(10);
      
		}
}

void setup() {
    Serial.begin(115200);
	// init can bus : baudrate = 500k
    while (CAN_OK != CAN.begin(CAN_500KBPS)) {
        Serial.println("CAN BUS Shield init fail");
        Serial.println("Init CAN BUS Shield again");
        delay(100);
    }
	epoch[7]=1;
	//Initilize Masks and Filters 
	//Different ECU nodes need different Masks and Filters initilization to receive different message
    CAN.init_Mask(0, 1, 0xffffffff); // Theoretically support up to 16^3 MIDs
    CAN.init_Mask(1, 1, 0xffffffff); // Theoretically support up to 16^3 MIDs
    CAN.init_Filt(0, 1, EID*0x100000 + 1); // KDMSG ID
    CAN.init_Filt(1, 1, EID*0x100000 + 2); // KDMSG ID
    Serial.println("CAN BUS Shield init ok!");
    Serial.print("SKDC Node. EID = 0x");
    Serial.println(EID, HEX);
    counter = 0;
}


void loop() {
  uint8_t len = 8;
  uint8_t buf[8];
  unsigned long canId;
  uint8_t new_epoch[8];
  uint8_t tmp_encrypted_key[16];
  uint8_t hmac[8];
  uint8_t flag;
  unsigned long MID; // 
 
  if (CAN_MSGAVAIL == CAN.checkReceive())  // check if data coming
  {
    CAN.readMsgBuf(&len, buf);    // read data

    canId = CAN.getCanId();
//      Serial.println("-----------------------------");
//      Serial.print("get data with MSG ID: 0x");
//      Serial.println(canId, HEX);
//
//      for (int i = 0; i < len; i++) { // print the data
//          Serial.print(buf[i],HEX);
//          Serial.print("\t");
//      }
//      Serial.println();

    if(canId >= EID*0x100000+1 && canId < EID*0x100000+0xfff)
    {
      MID = canId - EID*0x100000;
    }
    else
    {
      Serial.println("MSG ID unsupported.");
      return;
    }
    
    switch(counter%4)
    {
      case 0:
        array_assignment(new_epoch,buf,8);
        if(new_epoch[7]==1)
        {
          flag = 0;
        }
        else
        {
          flag = 1;
        }
        break;
      case 1:
        array_assignment(tmp_encrypted_key, buf, 8);
        break;
      case 2:
        array_assignment(&tmp_encrypted_key[8], buf, 8);
        break;
      case 3:
        array_assignment(hmac,buf,8);
        recover_session_key(tmp_encrypted_key, MID-1);
        flag = check_hmac(canId, hmac, MID-1);
        break;
    }
    counter++;
    
    if(counter >= 4*M)
		{
      for(int repeat=0;repeat<5;repeat++)
      {
        send_back_message(flag);
//        delay(3);
      }
      counter = 0;
      Serial.println();
      display_session_key();
    }     
  }
}

//END FILE
