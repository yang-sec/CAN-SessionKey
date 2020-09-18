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



/* PLEASE CHANGE TO SEE DIFFERENT SETUPS */
const int M=1; // Number of MSG IDs. Please fix M = 1.
const int N=6; // Number of normal ECUs with the max of 6. {2,3,4,5,6} are used in the paper. 

const int ArtDELAY = 50; // Artifitial delay

uint8_t epoch[8]={0,0,0,0,0,0,0,0};
uint8_t Pre_shared_key[6][16]={ // We simulate up to 6 ECUs with 2 Uno boards
  {0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28},  // ECU 1 at Uno 1
  {0x2c,0xeb,0x89,0x11,0x5e,0x74,0xe6,0xd8,0xf6,0x8d,0xe2,0x33,0xad,0xb7,0x7b,0x4f}, // ECU 1 at Uno 2
  {0x4f,0x9d,0xae,0xca,0xe3,0x15,0xad,0xf8,0x2d,0x73,0x39,0x83,0x29,0x99,0xcb,0x3c}, // ECU 2 at Uno 1
  {0xc1,0x3d,0x28,0xec,0x84,0xe6,0xb7,0x49,0x9e,0xd7,0xa9,0x7e,0xdd,0x4,0x8f,0xf6},  // ECU 2 at Uno 2
  {0x5b,0x47,0x27,0xe8,0x3c,0xb,0xf1,0x36,0xee,0x93,0xb,0x35,0x76,0xed,0x6a,0x2},    // ECU 3 at Uno 1
  {0x1b,0x28,0xde,0x9b,0xd6,0x9c,0xb4,0x6,0x77,0xf5,0x4f,0xb7,0xd4,0x15,0x78,0x76} // ECU 3 at Uno 2
};

//unsigned long EID[3]={0x000800,0x001800,0x002800};
unsigned long EID[6]={0x000800, 0x001000, 0x001800, 0x002000, 0x002800, 0x003000};
//unsigned long CID[3][M];
int counter[N];
int counterTT;

//Initialize time variable for elapse time calculation
double start0, start1, start2, end0, endt1, endt2, elapsed0, elapsed1, elapsed2;
uint8_t Session_key[M][16];

// Tmp variables
uint8_t Encrypted_key[16];
uint8_t hmac[8];
bool finished;
                 
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
//	for(int m=0;m<M;m++){
//    Serial.println("Session key generated:");
//    for(int k=0;k<16;k++){
//      Serial.print(Session_key[m][k], HEX);
//      Serial.print("\t");
//    }
//    Serial.println();
//	}
}

// Send out KDMSG to a certain ECU e for MSG m
void send_kdmsg(int e, int m)
{
    unsigned long MID;
    MID = EID[e] + m + 1;
//    Serial.print("------- KDMSG with ID: ");
//    Serial.print(MID,HEX);
//    Serial.print(" sent to node ");
//    Serial.print(e);
//    Serial.println(" -------");
   
    AES128.setKey(Pre_shared_key[e],16);
    AES128.encryptBlock(Encrypted_key,Session_key[m]);
    hash.resetHMAC(Pre_shared_key[e], 16);
    hash.update(&MID, sizeof(MID));
    hash.update(epoch, 8);
    hash.update(Session_key[m], 16);
    hash.finalizeHMAC(Pre_shared_key[e], 16, hmac, 8);
    
    CAN.sendMsgBuf(MID, 1, 8, epoch);
//    Serial.print("Epoch:\t");
//    for (int i = 0; i < 8; i++) { // print the data
//          Serial.print(epoch[i],HEX);
//          Serial.print("\t");
//    }
//    Serial.println();
//    delay(ArtDELAY);
    
    CAN.sendMsgBuf(MID, 1, 8, Encrypted_key);
//    Serial.print("EnKey1:\t");
//    for (int i = 0; i < 8; i++) { // print the data
//          Serial.print(Encrypted_key[i],HEX);
//          Serial.print("\t");
//    }
//    Serial.println();
//    delay(ArtDELAY);

    CAN.sendMsgBuf(MID, 1, 8, &Encrypted_key[8]);
//    Serial.print("EnKey2:\t");
//    for (int i = 0; i < 8; i++) { // print the data
//          Serial.print(Encrypted_key[i+8],HEX);
//          Serial.print("\t");
//    }
//    Serial.println();
//    delay(ArtDELAY);
    
    CAN.sendMsgBuf(MID, 1, 8, hmac);
//    Serial.print("HMAC:\t");
//    for (int i = 0; i < 8; i++) { // print the data
//          Serial.print(hmac[i],HEX);
//          Serial.print("\t");
//    }
//    Serial.println();
    delay(ArtDELAY);
}

//function for Hash checking
//Gurantee the message intergity
uint8_t check_message_digest(unsigned long MID, uint8_t MAC[8], int e){
	uint8_t tmp_MAC[8];
	uint8_t tmp_flag=0;
	hash.resetHMAC(Pre_shared_key[e], 16);
	hash.update(&MID, sizeof(MID));
	hash.update(epoch, 8);
	for(int j=0;j<M;j++){
		hash.update(Session_key[j], 16);
		}
	hash.finalizeHMAC(Pre_shared_key[e], 16, tmp_MAC, 8);
	for(int k=0;k<8;k++){
		if(MAC[e]!=tmp_MAC[e]){
			Serial.println(MAC[e]);
			Serial.println(tmp_MAC[e]);
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
    Serial.print("SKDC Key Server. #N = ");
    Serial.println(N);

    finished = false;
    for(int e=0;e<N;e++)
    {
      counter[e] = 0;
    }
    counterTT = 0;
    epoch[7]=1;
    elapsed0 = 0;
    
    start1 = micros();
    Session_key_generation();
    endt1 = micros();

    for(int m=0;m<M;m++)
    {
      Serial.println("Session key generated:");
      for(int k=0;k<16;k++)
      {
        Serial.print(Session_key[m][k], HEX);
        Serial.print("\t");
      }
      Serial.println();
    }

    start2 = micros();
    for(int m=0;m<M;m++)
    {
      start0 = micros();
      for(int e=0;e<N;e++)
      {    
          send_kdmsg(e,m);
      }
    }
    elapsed0 += micros() - start2;
      
//    counter=0;
    
}



void loop() {	
  
  uint8_t len = 8;
  uint8_t buf[8];
  unsigned long canId;
  uint8_t tmp_epoch[8];
  uint8_t flag;
  uint8_t MAC[8];
  int ecu;

  if (CAN_MSGAVAIL == CAN.checkReceive()) {         // check if data coming
    CAN.readMsgBuf(&len, buf);    // read data

    if(!finished)
    {
        canId = CAN.getCanId();
//        Serial.println("-----------------------------");
//        Serial.print("get data from CAN ID: 0x");
//        Serial.println(canId, HEX);
//        
//        for (int i = 0; i < len; i++) { // print the data
//          Serial.print(buf[i],HEX);
//          Serial.print("\t");
//        }
//        Serial.println();
    
        switch(canId)
        {
          case 0x010800:
            ecu = 0;
            break;
          case 0x011000:
            ecu = 1;
            break;
          case 0x011800:
            ecu = 2;
            break;
          case 0x012000:
            ecu = 3;
            break;
          case 0x012800:
            ecu = 4;
            break;
          case 0x013000:
            ecu = 5;
            break;
        }
    
        
        switch(counter[ecu])
        {
          case 0:
            array_assignment(tmp_epoch, buf, 8);
            if(tmp_epoch[7]==epoch[7])
            {
              flag=0;
            }
            else
            {
              flag=1;
            }
            break;
            
           case 1:
            array_assignment(MAC, buf, 8);
            flag=check_message_digest(canId, MAC, ecu);
            break;
        }
    
        if(counter[ecu]<2)
        {
          counter[ecu]++;
        }

        counterTT = 0;
        for(int e=0;e<N;e++)
        {
          counterTT +=counter[e];
        }
    
//        Serial.print("counter[");
//        Serial.print(ecu);
//        Serial.print("]: ");
//        Serial.print(counter[ecu]);
//        Serial.print("\t counterTT: ");
//        Serial.println(counterTT);
        
        if(counterTT>=2*N)
    		{
          
          if(flag==1){
           Serial.println();
           Serial.println("Confirmation Fail");
          }
          else{
            endt2 = micros();
    
            finished = true;
            Serial.println();
            Serial.println("Confirmation Success");
            elapsed1= endt1 - start1;
            elapsed2= endt2 - start2;
            
            Serial.println();
            Serial.print("Time for key generation (micro sec): ");
            Serial.print(elapsed1);
            Serial.println();
            Serial.print("Time for key distribution (micro sec): ");
            Serial.println(elapsed2);
            Serial.print("Sum (ms): ");
            Serial.println((elapsed1+elapsed2));
            Serial.print("Time for sending all KDMSGs minus artificial delays (micro sec): ");
            Serial.println(elapsed0 - ArtDELAY*1000*N);
            Serial.println();

//            for(int m=0;m<M;m++)
//            {
//              Serial.println("Session key distributed:");
//              for(int k=0;k<16;k++)
//              {
//                Serial.print(Session_key[m][k], HEX);
//                Serial.print("\t");
//              }
//              Serial.println();
//            }
          }
    
          for(int e=0;e<N;e++)
          {
            counter[e] = 0;
          }
          counterTT = 0;
    		}
    }
  }
}

// END FILE
