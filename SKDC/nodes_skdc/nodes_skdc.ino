//SKDC protocol, ECU node
//Shanghao Shi
//Protocol Implemention for ACSAC2020-Session key Distribution Make Practical for CAN and CAN-FD Message Authentication

#include "mcp_can.h"
#include <AES.h>
#include <SHA256.h>

const int M=1;
const int N=2;

//set CS pin
const int SPI_CS_PIN = 9;
MCP_CAN CAN(SPI_CS_PIN);

AESSmall128 AES128;
SHA256 hash;

uint8_t counter;
uint8_t Session_key[M][16];
uint8_t epoch[8]={0,0,0,0,0,0,0,0};
uint8_t Pre_shared_key[16]={0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};


void array_assignment(uint8_t *data1,uint8_t *data2, uint8_t data_len){
  for(int k=0;k<data_len;k++){
    data1[k]=data2[k];
    }  
  }

uint8_t recover_session_key(uint8_t encrypted_key[16], int i){
	AES128.setKey(Pre_shared_key, 16);
	AES128.decryptBlock(Session_key[i],encrypted_key);
	Serial.println("Session_key:");
	for(int k=0;k<16;k++){
		Serial.print(Session_key[i][k]);
		Serial.print("\t");
		}
	Serial.println();
  }
  
uint8_t check_hmac(unsigned long ID,uint8_t hmac[8], int i){
	uint8_t new_hmac[8];
	hash.resetHMAC(Pre_shared_key, 16);
	hash.update(&ID, sizeof(ID));
	hash.update(epoch, 8);
	hash.update(Session_key[i], 16);
	hash.finalizeHMAC(Pre_shared_key, 16, new_hmac, 8);
	for(int k=0;k<8;k++){
		if(new_hmac[k]!=hmac[k]){
			return 1;
			} 
		}
	return 0;
  }


void send_back_message(uint8_t flag){
	uint8_t new_hmac[8];
	if(flag==0){
			unsigned long ID=0x080000;
			hash.resetHMAC(Pre_shared_key, 16);
			hash.update(&ID, sizeof(ID));
			hash.update(epoch, 8);
			for(int j=0;j<M;j++){
				hash.update(Session_key[j], 16);
				}
			hash.finalizeHMAC(Pre_shared_key, 16, new_hmac, 8);
			CAN.sendMsgBuf(ID, 1, 8, epoch);
			delay(1);
			CAN.sendMsgBuf(ID, 1, 8, new_hmac);
			}
	else{ 
			unsigned long ID=0x080000*2;
			hash.resetHMAC(Pre_shared_key, 16);
			hash.update(&ID, sizeof(ID));
			hash.update(epoch, 8);
			hash.finalizeHMAC(Pre_shared_key, 16, new_hmac, 8);
			CAN.sendMsgBuf(ID, 1, 8, epoch);
			//delay(1);
			CAN.sendMsgBuf(ID, 1, 8, new_hmac);
		}
  }

void setup() {
    Serial.begin(9600);
	// init can bus : baudrate = 500k
    while (CAN_OK != CAN.begin(CAN_500KBPS)) {
        Serial.println("CAN BUS Shield init fail");
        Serial.println("Init CAN BUS Shield again");
        delay(100);
    }
	epoch[7]=1;
	//Initilize Masks and Filters
	//Different ECU nodes need different Masks and Filters initilization to receive different message
    CAN.init_Mask(0, 1, 0x1fffffff);
    CAN.init_Mask(1, 1, 0x1fffffff);
    CAN.init_Filt(0, 1, 0x01);
    CAN.init_Filt(1, 1, 0x100001);
    
    Serial.println("CAN BUS Shield init ok!");
    counter=0;
    
}


void loop() {
    uint8_t len = 8;
    uint8_t buf[8];
    unsigned long canId;
	  uint8_t new_epoch[8];
	  uint8_t tmp_encrypted_key[16];
	  uint8_t hmac[8];
	  uint8_t flag;
    if (CAN_MSGAVAIL == CAN.checkReceive()) {// check if data coming
        CAN.readMsgBuf(&len, buf);    // read data

        canId = CAN.getCanId();
        Serial.println("-----------------------------");
        Serial.println("get data from ID: 0x");
        Serial.println(canId, HEX);

        for (int i = 0; i < len; i++) { // print the data
            Serial.print(buf[i]);
            Serial.print("\t");
        }
        Serial.println();
		for(int i=0;i<M;i++){
				if(counter==4*i+0){
					array_assignment(new_epoch,buf,8);
					if(new_epoch[7]==1){
						flag=0;
					}
					else{
						flag=1;
					}
				}
				else if(counter==4*i+1){
					array_assignment(tmp_encrypted_key,buf,8);
				}
				else if(counter==4*i+2){
					array_assignment(&tmp_encrypted_key[8],buf,8);
					recover_session_key(tmp_encrypted_key,i);
				}
				else if(counter==4*i+3){
					array_assignment(hmac,buf,8);
					flag=check_hmac(canId, hmac, i);
				}		
		}
		counter++;
		if(counter==4*M){
			counter=0;
			send_back_message(flag);
		}
    }
}

//END FILE
