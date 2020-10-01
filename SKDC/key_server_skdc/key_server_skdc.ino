// SKDC protocol, Key Server
// Shanghao Shi, Yang Xiao
// Protocol Implemention for ACSAC2020-Session key Distribution Make Practical for CAN and CAN-FD Message Authentication

#include <mcp_can.h>
#include <AES.h>
//#include <SHA256.h>
#include <BLAKE2s.h>
#include <RNG.h>


/* PLEASE CHANGE TO SEE DIFFERENT SETUPS */
const int M=1; // Number of MSG IDs.
const int N=6; // Number of normal ECUs with the max of 6. 

const int KdDELAY_Micro = 6800; // Artifitial delay 

uint8_t Pre_shared_key[6][16]={ // We simulate up to 6 ECUs with 2 Uno boards
  {0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28},  // ECU 1
  {0x2c,0xeb,0x89,0x11,0x5e,0x74,0xe6,0xd8,0xf6,0x8d,0xe2,0x33,0xad,0xb7,0x7b,0x4f}, // ECU 2
  {0x4f,0x9d,0xae,0xca,0xe3,0x15,0xad,0xf8,0x2d,0x73,0x39,0x83,0x29,0x99,0xcb,0x3c}, // ECU 3
  {0xc1,0x3d,0x28,0xec,0x84,0xe6,0xb7,0x49,0x9e,0xd7,0xa9,0x7e,0xdd,0x4,0x8f,0xf6},  // ECU 4
  {0x5b,0x47,0x27,0xe8,0x3c,0xb,0xf1,0x36,0xee,0x93,0xb,0x35,0x76,0xed,0x6a,0x2},    // ECU 5
  {0x57,0x03,0x42,0xbc,0x18,0xfb,0xb1,0xf0,0x62,0x1d,0x50,0x68,0x2a,0xc,0x4a,0x51}   // ECU 6
};

// Set CS pin
const int SPI_CS_PIN = 9;
MCP_CAN CAN(SPI_CS_PIN);

AESTiny128 AES128;
BLAKE2s hash;

unsigned long EID[6]={0x001, 0x002, 0x003, 0x004, 0x005, 0x006}; // Within 8 bits
int counter[N];
int counterTT;

//Initialize time variable for elapse time calculation
double t0, t1, t2, t3, t4, t5;

uint8_t Session_key[M][16];
uint8_t epoch[8]={0};

// Tmp variables
uint8_t Encrypted_key[16];
uint8_t hmac[8];
bool finished;
bool finishedECU[N];
uint8_t conf_flag;
                 
void array_assignment(uint8_t *data1,uint8_t *data2, uint8_t data_len)
{
  for(int k=0;k<data_len;k++)
  {
    data1[k]=data2[k];
  } 
}

// Generate session key and broadcast it to all ECU nodes
// Time delay is added to make CAN protocol work more smoothly
void Session_key_generation()
{
	RNG.begin("Session_key_generation");
	RNG.rand(&Session_key[0][0], M*16);
}

// Send out KDMSGs per ECU per MSG
void send_kdmsg(int e, int m)
{
  unsigned long ID;
  ID = (0x100+EID[e])*0x100000 + (m+1)*0x100;

  AES128.setKey(Pre_shared_key[e], 16);
  AES128.encryptBlock(Encrypted_key, Session_key[m]);
  hash.reset(Pre_shared_key[e], 16, 8);
  hash.update(&ID, sizeof(ID));
  hash.update(epoch, 8);
  hash.update(Session_key[m], 16);
  hash.finalize(hmac, 8);
  
  CAN.sendMsgBuf(ID, 1, 8, epoch);
  CAN.sendMsgBuf(ID+1, 1, 8, Encrypted_key);
  CAN.sendMsgBuf(ID+2, 1, 8, &Encrypted_key[8]);
  CAN.sendMsgBuf(ID+3, 1, 8, hmac);
}

// Function for Hash checking on CO_MSG
uint8_t check_message_digest(unsigned long ID, uint8_t MAC[8], int e)
{
	uint8_t tmp_MAC[8];
	uint8_t tmp_flag = 0;
//	hash.resetHMAC(Pre_shared_key[e], 16);
  hash.reset(Pre_shared_key[e], 16, 8);
	hash.update(&ID, sizeof(ID));
	hash.update(epoch, 8);
	for(int j=0;j<M;j++)
	{
		hash.update(Session_key[j], 16);
	}
  hash.finalize(tmp_MAC, 8);
  
	for(int k=0;k<8;k++)
	{
		if(MAC[e]!=tmp_MAC[e])
		{
			Serial.println(MAC[e]);
			Serial.println(tmp_MAC[e]);
			return 1;
		}
	}
  return 0;
}


void setup() 
{
    Serial.begin(115200);
	// init can bus : baudrate = 500k
    while (CAN_OK != CAN.begin(CAN_500KBPS)) {
        Serial.println("CAN BUS Shield init fail");
        Serial.println(" Init CAN BUS Shield again");
        delay(100);
    }    
    Serial.println("CAN BUS Shield init ok!");
    Serial.print("SSKT Key Server. N = ");
    Serial.print(N);
    Serial.print(", M = ");
    Serial.println(M);

    finished = false;
    for(int e=0;e<N;e++)
    {
      finishedECU[e] = false;
      counter[e] = 0;
    }
    counterTT = 0;
    epoch[7] = 1;
    conf_flag = 0;
    
    t0 = micros();
    Session_key_generation();
    t1 = micros();

    Serial.println();
    Serial.println("Session keys generated:");
    for(int m=0;m<M;m++)
    {
      for(int b=0;b<16;b++)
      {
        Serial.print(Session_key[m][b], HEX);
        Serial.print(" ");
      }
      Serial.println();
    }

    t2 = micros();
    t3 = micros();
    
    for(int m=0;m<M;m++)
    {
      for(int n=0;n<N;n++)
      {    
          send_kdmsg(n, m);
      }
      if(m < M-1)
      {
        delayMicroseconds(KdDELAY_Micro); // Inter-KDMSG delay, giving ECU time to compute
      }
    }
    t4 = micros();
}


void loop()
{	
  uint8_t len = 8;
  uint8_t buf[8];
  unsigned long canId;
  uint8_t tmp_epoch[8];
  uint8_t MAC[8];
  int ecu;

  if (CAN_MSGAVAIL == CAN.checkReceive()) {         // check if data coming
    CAN.readMsgBufID(&canId, &len, buf);    // read data

    if(!finished)
    {
//      canId = CAN.getCanId();
//      Serial.println("-----------------------------");
//      Serial.print("get data from CAN ID: 0x");
//      Serial.println(canId, HEX);
//      
//      for (int i = 0; i < len; i++) { // print the data
//        Serial.print(buf[i],HEX);
//        Serial.print("\t");
//      }
//      Serial.println();

      ecu = canId - 0x201;

      if(finishedECU[ecu])
      {
        return;
      }
  
      switch(counter[ecu])
      {
        case 0:
          array_assignment(tmp_epoch, buf, 8);
          if(tmp_epoch[7]!=epoch[7])
          {
            Serial.println("CO_MSG outdated.");
            return;
          }
          break;  
        case 1:
          array_assignment(MAC, buf, 8);
          conf_flag += check_message_digest(canId, MAC, ecu);
          finishedECU[ecu] = true;
          break;
      }

      if(counter[ecu] < 2)
      {
        counter[ecu]++;
      }

      counterTT = 0;
      for(int e=0;e<N;e++)
      {
        counterTT +=counter[e];
      }
        
      if(counterTT>=2*N)
      {
        t5 = micros();
        finished = true;
        Serial.println();
        if(conf_flag > 0)
        {
          Serial.println("Confirmation Fail");
        }
        else
        {
          Serial.println("Confirmation Success");
        }
                
        Serial.println();
        Serial.print("Time for key generation (ms): ");
        Serial.println((t1-t0)/1000);
        Serial.print("Time for entire session after key generation (ms): ");
        Serial.println((t5-t2)/1000);
        
        Serial.println();
  
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
