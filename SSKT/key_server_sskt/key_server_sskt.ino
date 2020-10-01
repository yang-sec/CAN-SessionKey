//SSKT protocol, Key Server
//Shanghao Shi, Yang Xiao
//Protocol Implemention for ACSAC2020-Session key Distribution Make Practical for CAN and CAN-FD Message Authentication

#include <mcp_can.h>
#include <SPI.h>
//#include <SHA256.h>
#include <AES.h>
#include <BLAKE2s.h>
#include <GF256.h>
#include <RNG.h>
#include <Crypto.h>


/* PLEASE CHANGE TO SEE DIFFERENT SETUPS */
const int M=6; // Number of MSG IDs. Please fix M=1.
const int N=4; // Number of normal ECUs with the max of 5. {1,2,3,4,5} are used in the paper. 

const int PrDELAY_Micro = 5700, KdDELAY_Micro = 5500, KdOFFSET_Micro = 0; // Artifitial delay  


uint8_t Pre_shared_key_x[6][16]={
  {0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28},  // ECU 0
  {0x2c,0xeb,0x89,0x11,0x5e,0x74,0xe6,0xd8,0xf6,0x8d,0xe2,0x33,0xad,0xb7,0x7b,0x4f}, // ECU 1
  {0x4f,0x9d,0xae,0xca,0xe3,0x15,0xad,0xf8,0x2d,0x73,0x39,0x83,0x29,0x99,0xcb,0x3c}, // ECU 2
  {0xc1,0x3d,0x28,0xec,0x84,0xe6,0xb7,0x49,0x9e,0xd7,0xa9,0x7e,0xdd,0x4,0x8f,0xf6},  // ECU 3
  {0x5b,0x47,0x27,0xe8,0x3c,0xb,0xf1,0x36,0xee,0x93,0xb,0x35,0x76,0xed,0x6a,0x2},    // ECU 4
  {0x57,0x03,0x42,0xbc,0x18,0xfb,0xb1,0xf0,0x62,0x1d,0x50,0x68,0x2a,0xc,0x4a,0x51}   // ECU 5
};
uint8_t Pre_shared_key_y[6][16]={
  {0x33,0x69,0x92,0x70,0x1c,0x3a,0xad,0x5,0x75,0x5b,0x9b,0x64,0x3f,0x9b,0x72,0xbd},  // ECU 0
  {0xce,0xda,0x31,0x94,0x8e,0x39,0xdd,0x10,0x4a,0xe5,0xe4,0xfb,0xcd,0x2e,0x64,0x27}, // ECU 1
  {0x34,0xbb,0xf7,0x19,0x2b,0x85,0x28,0x90,0x53,0x7b,0x5f,0x6a,0x7e,0xbd,0xd6,0xfd}, // ECU 2
  {0x96,0xd7,0xd0,0x92,0x7,0x42,0xe4,0xca,0x28,0xb6,0xac,0x59,0x60,0xab,0xa9,0xa6},  // ECU 3
  {0xe,0x1,0x23,0xd2,0x1c,0x1f,0x14,0xff,0x73,0xf0,0x95,0xab,0x52,0xae,0x3,0x8b},    // ECU 4
  {0x7d,0x5d,0x61,0xca,0x93,0x89,0xeb,0xa4,0x2d,0xb8,0xd,0xbc,0x8b,0x83,0x41,0xa6}   // ECU 5
};
  
//Set CS pin
const int SPI_CS_PIN = 9;
MCP_CAN CAN(SPI_CS_PIN);
BLAKE2s hash;
AESTiny128 AES128;
  
uint8_t auxX_All[6]={0xfc,0xf2,0xc3,0x8,0x13,0x75}; // Same aux x coordinate for every byte

unsigned long EID[6]={0x001, 0x002, 0x003, 0x004, 0x005, 0x006}; // Within 8 bits
int counter[N];
int counterTT;

//Initialize time variables for elapse time calculation
double t0, t1, t2, t3, t4, t5;

uint8_t Session_key[M][16];
uint8_t epoch[8]={0};


// Tmp variables
uint8_t auxX[N];
uint8_t auxY[N][16];
uint8_t R[N][16];
bool finished;
bool finishedECU[N];
uint8_t conf_flag;




void array_assignment(uint8_t *array_1, uint8_t *array_2, uint8_t array_len)
{
  for(int i=0;i<array_len;i++)
  {
    array_1[i]=array_2[i];
  }
}


// Also include the preparation work for secret sharing
void Session_key_generation()
{ 
  RNG.begin("Session_key_generation");
  RNG.rand(&Session_key[0][0], M*16);
  RNG.rand(&R[0][0], N*16);
}

void send_prmsg(uint8_t n)
{
  uint8_t hmac[8];
  unsigned long ID = EID[n]*0x100000;

  hash.reset(Pre_shared_key_x[n], 16, 8); // BLAKE2s keyed mode
  hash.update(&ID, sizeof(ID));
  hash.update(epoch, 8);
  hash.update(&R[n][0], 16);
  hash.finalize(hmac, 8);
  
  CAN.sendMsgBuf(ID, 1, 8, epoch, true);
  CAN.sendMsgBuf(ID+1, 1, 8, &R[n][0], true);
  CAN.sendMsgBuf(ID+2, 1, 8, &R[n][8], true);
  CAN.sendMsgBuf(ID+3, 1, 8, hmac, true);
  
//  Serial.println(ID, HEX);
//  for(int b=0;b<8;b++)
//  { 
//    Serial.print(epoch[b], HEX);
//    Serial.print(" ");
//  }
//  Serial.println();
//  for(int b=0;b<8;b++)
//  { 
//    Serial.print(R[n][b], HEX);
//    Serial.print(" ");
//  }
//  Serial.println();
//  for(int b=0;b<8;b++)
//  { 
//    Serial.print(R[n][b+8], HEX);
//    Serial.print(" ");
//  }
//  Serial.println();
//  for(int b=0;b<8;b++)
//  { 
//    Serial.print(hmac[b], HEX);
//    Serial.print(" ");
//  }
//  Serial.println();
}

void send_kdmsg(int m)
{
  uint8_t hmac[8];
//  uint8_t Rm[N][16];
  uint8_t points_x[N+1];
  uint8_t points_y[N+1];
  
  unsigned long MID = (m + 1)*0x100;
  unsigned long ID = 0x10000000 + MID; // CAN ID

  // Compute the Rms for this MID
  for(int n=0;n<N;n++)
  {
//    Serial.println();
//    for(int b=0;b<8;b++)
//    {
//      Serial.print(R[n][b],HEX);
//      Serial.print(" ");
//    }
//    Serial.println();

//    hash.reset();
//    hash.update(&Pre_shared_key_y[n][0], 16);
//    hash.update(&R[n][0], 16);
//    hash.update(&MID, sizeof(MID));
//    hash.finalize(&R[n][0], 16);
    AES128.setKey(&Pre_shared_key_y[n][0], 16);
    AES128.encryptBlock(&R[n][0], &R[n][0]);
    
//    for(int b=0;b<8;b++)
//    {
//      Serial.print(R[n][b],HEX);
//      Serial.print(" ");
//    }
//    Serial.println();
  }
  // Compute the aux y points
  for(int b=0;b<16;b++)
  { 
    for(int i=0;i<N;i++)
    {
      points_x[i]=Pre_shared_key_x[i][b];
      points_y[i]=Pre_shared_key_y[i][b]^R[i][b];
    }
    points_x[N]=0;
    points_y[N]=Session_key[m][b];
    for(int i=0; i<N; i++)
    {
      auxY[i][b]=Largrange_interpolation(points_x,points_y,auxX[i]);
    }
  }

  hash.reset(Session_key[m], 16, 8); // BLAKE2s keyed mode
//  hash.update(Session_key[m], 16);
  hash.update(&ID, sizeof(ID));
  hash.update(epoch, 8);
  hash.finalize(hmac, 8);
  
  // Send out KD_MSG
  CAN.sendMsgBuf(ID, 1, 8, epoch, true);
  for(int n=0;n<N;n++)
  {
    CAN.sendMsgBuf(ID+2*n+1, 1, 8, &auxY[n][0], true);
    CAN.sendMsgBuf(ID+2*n+2, 1, 8, &auxY[n][8], true);
  }
  CAN.sendMsgBuf(ID+2*N+1, 1, 8, hmac, true);
}

uint8_t Largrange_interpolation(uint8_t points_x[N+1], uint8_t points_y[N+1], uint8_t x_coordinate)
{
  uint8_t y_coordinate=0;
  for(int i=0;i<N+1;i++)
  {
    uint8_t tmp=0;
    for(int j=0;j<N+1;j++)
    {
      if(j!=i)
      {
        tmp = ((tmp+GF256_Log[x_coordinate^points_x[j]])%0xff+GF256_Log[GF256_Inv[points_x[j]^points_x[i]]])%0xff;
      }
    }
    y_coordinate ^= (points_y[i] != 0x0)? GF256_Exp[(GF256_Log[points_y[i]]+tmp)%0xff] : 0x0;
  }
  return y_coordinate;
}

  
// Function for Hash checking on CO_MSG
uint8_t check_message_digest(unsigned long ID, uint8_t MAC[8], int e)
{
  uint8_t tmp_MAC[8];
  uint8_t tmp_flag = 0;
  hash.reset(Pre_shared_key_y[e], 16, 8); // BLAKE2s keyed mode
//  hash.update(Pre_shared_key_y[e], 16);
  hash.update(&ID, sizeof(ID));
  hash.update(epoch, 8);
  for(int m=0;m<M;m++)
  {
    hash.update(Session_key[m], 16);
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
  while (CAN_OK != CAN.begin(CAN_500KBPS)) 
  {
      Serial.println("CAN BUS Shield init fail");
      Serial.println(" Init CAN BUS Shield again");
      delay(100);
  }
  Serial.println("CAN BUS Shield init ok!");
  Serial.print("SSKT Key Server. N = ");
  Serial.print(N);
  Serial.print(", M = ");
  Serial.println(M);
  
  for(int e=0;e<N;e++)
  {
    finishedECU[e] = false;
    counter[e] = 0;
    auxX[e] = auxX_All[e];
  }
  counterTT = 0;
  epoch[7]=1;
  conf_flag = 0;
  
  t0 = micros();
  Session_key_generation();
  t1 = micros();

  Serial.println();
  Serial.println("Session key generated:");
  for(int m=0;m<M;m++)
  {
    Serial.print("MSG ");
    Serial.print(m+1, HEX);
    Serial.print(":\t");
    for(int b=0;b<16;b++)
    {
      Serial.print(Session_key[m][b], HEX);
      Serial.print(" ");
    }
    Serial.println();
  }

  t2 = micros();
  for(int n=0;n<N;n++)
  {    
    send_prmsg(n);
  }
  delayMicroseconds(PrDELAY_Micro);
  t3 = micros();
  
  for(int m=0;m<M;m++)
  {
    send_kdmsg(m);
    if(m < M-1)
    {
      delayMicroseconds(KdDELAY_Micro - KdOFFSET_Micro*N); // Inter-KDMSG delay, giving ECU time to compute
    }
  }
  t4 = micros(); 
}




void loop()
{
  uint8_t len;
  uint8_t buf[8];
  unsigned long canId;
  uint8_t tmp_epoch[8];
  uint8_t flag;
  uint8_t MAC[8];
  int ecu;

  if (CAN_MSGAVAIL == CAN.checkReceive()) 
  {         
    CAN.readMsgBufID(&canId, &len, buf); 

    if(!finished)
    {
//      canId = CAN.getCanId();
      
//      Serial.println("-----------------------------");
//      Serial.print("get data from ID: 0x");
//      Serial.println(canId, HEX);
//      for (int i = 0; i < len; i++) 
//      {
//          Serial.print(buf[i],HEX);
//          Serial.print("\t");
//      }
//      Serial.println();

//      // We explicitly list out the correspondence between (0x200+EID) and ECU index
//      switch(canId)
//      {
//        case 0x201:
//          ecu = 0;
//          break;
//        case 0x202:
//          ecu = 1;
//          break;
//        case 0x203:
//          ecu = 2;
//          break;
//        case 0x204:
//          ecu = 3;
//          break;
//        case 0x205:
//          ecu = 4;
//          break;
//      }
      ecu = canId - 0x201;

      if(finishedECU[ecu])
      {
        return;
      }

//      Serial.print("get data from ID: 0x");
//      Serial.println(canId, HEX);
//      for (int i = 0; i < len; i++) 
//      {
//          Serial.print(buf[i],HEX);
//          Serial.print("\t");
//      }
//      Serial.println();

   
      if(counter[ecu] == 0)
      {
        array_assignment(tmp_epoch, buf, 8);
        if(tmp_epoch[7] == epoch[7] && tmp_epoch[6] == epoch[6])
        {
//          Serial.print("ECU ");
//          Serial.print(ecu+1);
//          Serial.println("'s CO_MSG outdated.");
          counter[ecu] = 1;
        }
      }
      else if(counter[ecu] == 1)
      {
        array_assignment(MAC, buf, 8);
        conf_flag += check_message_digest(canId, MAC, ecu);
        finishedECU[ecu] = true;
        counter[ecu] = 2;
        counterTT += 2;
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
        Serial.print("Time for preparation (ms): ");
        Serial.println((t3-t2)/1000);
        Serial.print("Time for entire session after preparation (ms): ");
        Serial.println((t5-t3)/1000);
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
