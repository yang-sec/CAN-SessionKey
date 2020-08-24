//SKDC protocol, Key Server
//Shanghao Shi
//Protocol Implemention for ACSAC2020-Session key Distribution Make Practical for CAN and CAN-FD Message Authentication

#include <mcp_can.h>
#include <AES.h>
#include <SHA256.h>
#include <RNG.h>

// Set CS pin
const int SPI_CS_PIN = 9;
MCP_CAN CAN(SPI_CS_PIN);

AESTiny128 AES128;
SHA256 hash;

//Initialize time variable for elapse time calculation
double start1, start2, endt1, endt2, elapsed1, elapsed2;

//M is the number of session key and N is the number of ECU nodes,
//M N can be changed to simulate different network scale
const int M=1;
const int N=2;

uint8_t epoch[8]={0,0,0,0,0,0,0,0};

uint8_t Pre_shared_key[N][16]={{0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},{0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}};                    
uint8_t Session_key[M][16];
int counter;
                    
void array_assignment(uint8_t *data1,uint8_t *data2, uint8_t data_len){
  for(int k=0;k<data_len;k++){
    data1[k]=data2[k];
    }  
  }

//Generate session key and broadcast it to all ECU nodes
//Time delay is added to make CAN protocol work more smoothly
void Session_key_generation(){
	RNG.begin("Session_key_generation");
	RNG.rand(&Session_key[0][0], M*16);
	for(int i=0;i<M;i++){
		unsigned long ID=i+1;
		for(int j=0;j<N;j++){
			ID=ID+0x080000;
			uint8_t Encrypted_key[16];
			uint8_t hmac[8];
			AES128.setKey(Pre_shared_key[j],16);
			AES128.encryptBlock(Encrypted_key,Session_key[i]);
			hash.resetHMAC(Pre_shared_key[j], 16);
			hash.update(&ID, sizeof(ID));
			hash.update(epoch, 8);
			hash.update(Session_key[i], 16);
			hash.finalizeHMAC(Pre_shared_key[j], 16, hmac, 8);
			Serial.println("Session key:");
			for(int k=0;k<16;k++){
				Serial.print(Session_key[i][k]);
				Serial.print("\t");
			}
			Serial.println();
			CAN.sendMsgBuf(ID, 1, 8, epoch);
			delay(1);
			CAN.sendMsgBuf(ID, 1, 8, Encrypted_key);
			delay(1);
			CAN.sendMsgBuf(ID, 1, 8, &Encrypted_key[8]);
			delay(1);
			CAN.sendMsgBuf(ID, 1, 8, hmac);
			delay(1);
		}
	}
	
	
}

//function for Hash checking
//Gurantee the message intergity
uint8_t check_message_digest(unsigned long ID, uint8_t MAC[8], int i){
	uint8_t tmp_MAC[8];
	uint8_t tmp_flag=0;
	hash.resetHMAC(Pre_shared_key[i], 16);
	hash.update(&ID, sizeof(ID));
	hash.update(epoch, 8);
	for(int j=0;j<M;j++){
		hash.update(Session_key[j], 16);
		}
	hash.finalizeHMAC(Pre_shared_key[i], 16, tmp_MAC, 8);
	for(int k=0;k<8;k++){
		if(MAC[i]!=tmp_MAC[i]){
			Serial.println(MAC[i]);
			Serial.println(tmp_MAC[i]);
			return 1;
			} 
		}
  return 0;
}


void setup() {
    Serial.begin(115200);
	// init can bus : baudrate = 500k
    while (CAN_OK != CAN.begin(CAN_500KBPS)) {
        Serial.println("CAN BUS Shield init fail");
        Serial.println(" Init CAN BUS Shield again");
        delay(100);
    }
    Serial.println("CAN BUS Shield init ok!");
    start1 = micros();
    epoch[7]=1;
    Session_key_generation();
    counter=0;
    endt1 = micros();
}


void loop() {
	start2= micros();
    uint8_t len = 8;
    uint8_t buf[8];
    unsigned long canId;
	uint8_t tmp_epoch[8];
	uint8_t flag;
	uint8_t MAC[8];
    if (CAN_MSGAVAIL == CAN.checkReceive()) {         // check if data coming
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
		for(int i=0;i<N;i++){
			if(counter==2*i){
				array_assignment(tmp_epoch , buf, 8);
				if(tmp_epoch[7]==epoch[7]){
					flag=0;
				}
				else{
					flag=1;
				}
			}
			else if(counter==2*i+1){
				array_assignment(MAC , buf, 8);
				flag=check_message_digest(canId, MAC, i);
			}
		}
		
		counter++;
		if(counter==2*N){
			counter=0;
      if(flag==1){
       Serial.println("Fail");
      }
      else{
        Serial.println("Success");
        endt2 = micros();
        elapsed1= endt1 - start1;
        elapsed2= endt2 - start2;
        Serial.println("Elapsed time:");
        Serial.println(elapsed1);
        Serial.println(elapsed2);
		//Protocol time = elapsed1 + elapsed2 - added time delay
      }
		}
   
    }
}

// END FILE
