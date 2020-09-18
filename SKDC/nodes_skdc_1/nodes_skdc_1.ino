//SKDC protocol, ECU node
//Shanghao Shi
//Protocol Implemention for ACSAC2020-Session key Distribution Make Practical for CAN and CAN-FD Message Authentication

#include "mcp_can.h"
#include <AES.h>
#include <SHA256.h>

const int M=1; // Number of MSG IDs. Please fix M = 1.
const int N=1; // Number of normal ECUs with the max of 3 at each Uno board

//set CS pin
const int SPI_CS_PIN = 9;
MCP_CAN CAN(SPI_CS_PIN);

AESSmall128 AES128;
SHA256 hash;

//uint8_t counter;
uint8_t Session_key[M][16];
uint8_t epoch[8]={0,0,0,0,0,0,0,0};
uint8_t Pre_shared_key[3][16]={ // Each Uno board simulate up to 3 ECUs
  {0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28},
  {0x4f,0x9d,0xae,0xca,0xe3,0x15,0xad,0xf8,0x2d,0x73,0x39,0x83,0x29,0x99,0xcb,0x3c},
  {0x5b,0x47,0x27,0xe8,0x3c,0xb,0xf1,0x36,0xee,0x93,0xb,0x35,0x76,0xed,0x6a,0x2}};

unsigned long EID[3]={0x000800,0x001800,0x002800};
int counter[N];
int counterTT;


void array_assignment(uint8_t *data1,uint8_t *data2, uint8_t data_len){
  for(int k=0;k<data_len;k++){
    data1[k]=data2[k];
    }  
  }

uint8_t recover_session_key(uint8_t encrypted_key[16], int e, int m){
	AES128.setKey(Pre_shared_key[e], 16);
	AES128.decryptBlock(Session_key[m],encrypted_key);
//	Serial.print("------- [ECU ");
//  Serial.print(e);
//  Serial.println("] get session key -------");
//  
//	for(int k=0;k<16;k++){
//		Serial.print(Session_key[m][k],HEX);
//		Serial.print("\t");
//	}
//	Serial.println();
}

uint8_t display_session_key(int e, int m)
{
  Serial.print("------- [ECU ");
  Serial.print(e);
  Serial.println("] get session key -------");
  for(int k=0;k<16;k++){
    Serial.print(Session_key[m][k],HEX);
    Serial.print("\t");
  }
  Serial.println();
}
  
uint8_t check_hmac(unsigned long ID, uint8_t hmac[8], int e, int m){
	uint8_t new_hmac[8];
	hash.resetHMAC(Pre_shared_key[e], 16);
	hash.update(&ID, sizeof(ID));
	hash.update(epoch, 8);
	hash.update(Session_key[m], 16);
	hash.finalizeHMAC(Pre_shared_key[e], 16, new_hmac, 8);
	for(int k=0;k<8;k++){
		if(new_hmac[k]!=hmac[k]){
			return 1;
			} 
		}
	return 0;
  }


void send_back_message(uint8_t flag, int ecu){
	uint8_t new_hmac[8];

  unsigned long ID = 0x010000 + EID[ecu];
  hash.resetHMAC(Pre_shared_key[ecu], 16);
  hash.update(&ID, sizeof(ID));
  hash.update(epoch, 8);
      
	if(flag==0){
			
			for(int j=0;j<M;j++){
				hash.update(Session_key[j], 16);
			}
  			hash.finalizeHMAC(Pre_shared_key[ecu], 16, new_hmac, 8);

//        Serial.print("------- [ECU ");
//        Serial.print(ecu);
//        Serial.print("] send COMSG with ID ");
//        Serial.print(ID,HEX);
//        Serial.println(" -------");
    
  			CAN.sendMsgBuf(ID, 1, 8, epoch);
//        Serial.print("Epoch:\t");
//        for (int i = 0; i < 8; i++) { // print the data
//              Serial.print(epoch[i],HEX);
//              Serial.print("\t");
//        }
//        Serial.println();
  			
  			CAN.sendMsgBuf(ID, 1, 8, new_hmac);
//        Serial.print("HMAC:\t");
//        for (int i = 0; i < 8; i++) { // print the data
//              Serial.print(new_hmac[i],HEX);
//              Serial.print("\t");
//        }
//        Serial.println();
			}
	else{ 
//      Serial.println("[KDMSG MAC does not check]");
			hash.finalizeHMAC(Pre_shared_key[ecu], 16, new_hmac, 8);
			CAN.sendMsgBuf(ID, 1, 8, epoch);
//			delay(10);
			CAN.sendMsgBuf(ID, 1, 8, new_hmac);
//      delay(10);
      
		}
}

void setup() {
    Serial.begin(19200);
	// init can bus : baudrate = 500k
    while (CAN_OK != CAN.begin(CAN_500KBPS)) {
        Serial.println("CAN BUS Shield init fail");
        Serial.println("Init CAN BUS Shield again");
        delay(100);
    }
	epoch[7]=1;
	//Initilize Masks and Filters
	//Different ECU nodes need different Masks and Filters initilization to receive different message
    CAN.init_Mask(0, 1, 0x1fffff00);
    CAN.init_Mask(1, 1, 0x1fffff00);
    CAN.init_Filt(0, 1, EID[0]+1); // KDMSG ID for ECU 0
    CAN.init_Filt(1, 1, EID[1]+1); // KDMSG ID for ECU 1
    CAN.init_Filt(2, 1, EID[2]+1); // KDMSG ID for ECU 2
    Serial.println("CAN BUS Shield init ok!");

    for(int e=0;e<N;e++)
    {
        counter[e] = 0;
    }
}


void loop() {
    uint8_t len = 8;
    uint8_t buf[8];
    unsigned long canId;
	  uint8_t new_epoch[8];
	  uint8_t tmp_encrypted_key[N][16];
	  uint8_t hmac[8];
	  uint8_t flag[N];

    int ecu; // up to N
   
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

      if(canId==EID[0]+1)
      {
          ecu = 0;
      }
      else if(canId==EID[1]+1)
      {
          ecu = 1;
      }
      else if(canId==EID[2]+1)
      {
          ecu = 2;
      }
      else
      {
        Serial.println("Unknow CAN ID");
        return;
      }

      
      switch(counter[ecu])
      {
        case 0:
          array_assignment(new_epoch,buf,8);
          if(new_epoch[7]==1)
          {
            flag[ecu]=0;
          }
          else
          {
            flag[ecu]=1;
          }
          break;
        case 1:
          array_assignment(tmp_encrypted_key[ecu], buf, 8);
          break;
        case 2:
          array_assignment(&tmp_encrypted_key[ecu][8], buf, 8);
          break;
        case 3:
          array_assignment(hmac,buf,8);
          recover_session_key(tmp_encrypted_key[ecu], ecu, 0);
          flag[ecu] = check_hmac(canId, hmac, ecu, 0);

//          send_back_message(flag[ecu], ecu);
          break;
      }
     
  		if(counter[ecu]<4)
      {
        counter[ecu]++;
      }

      counterTT = 0;
      for(int e=0;e<N;e++)
      {
        counterTT += counter[e];
      }

//      Serial.print("counter[");
//      Serial.print(ecu);
//      Serial.print("]: ");
//      Serial.print(counter[ecu]);
//      Serial.print("\t counterTT: ");
//      Serial.println(counterTT);
      
      if(counterTT >= 4*N)
  		{
        for(int repeat=0;repeat<7;repeat++)
        {
          for(int e=0;e<N;e++)
          {
            send_back_message(flag[e], e);
            delay(3);
          }
        }
        Serial.println();
        for(int e=0;e<N;e++)
        {
          display_session_key(e,0);
          counter[e] = 0;
        }
      }     
    }
}

//END FILE
