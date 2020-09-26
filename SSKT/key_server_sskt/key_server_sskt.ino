//SKDC protocol, Key Server
//Shanghao Shi
//Protocol Implemention for ACSAC2020-Session key Distribution Make Practical for CAN and CAN-FD Message Authentication

#include <mcp_can.h>
#include <SPI.h>
#include <SHA256.h>
#include <GF256.h>
#include <RNG.h>
#include <Crypto.h>

SHA256 hash;

//Set CS pin
const int SPI_CS_PIN = 9;
MCP_CAN CAN(SPI_CS_PIN);

/* PLEASE CHANGE TO SEE DIFFERENT SETUPS */
const int M=1; // Number of MSG IDs. Please fix M=1.
const int N=1; // Number of normal ECUs with the max of 6. {2,3,4,5,6} are used in the paper. 

const int ArtDELAY = 50; // Artifitial delay  


uint8_t Pre_shared_key_x[6][16]={
  {0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28},  // ECU 0
  {0x2c,0xeb,0x89,0x11,0x5e,0x74,0xe6,0xd8,0xf6,0x8d,0xe2,0x33,0xad,0xb7,0x7b,0x4f}, // ECU 1
  {0x4f,0x9d,0xae,0xca,0xe3,0x15,0xad,0xf8,0x2d,0x73,0x39,0x83,0x29,0x99,0xcb,0x3c}, // ECU 2
  {0xc1,0x3d,0x28,0xec,0x84,0xe6,0xb7,0x49,0x9e,0xd7,0xa9,0x7e,0xdd,0x4,0x8f,0xf6},  // ECU 3
  {0x5b,0x47,0x27,0xe8,0x3c,0xb,0xf1,0x36,0xee,0x93,0xb,0x35,0x76,0xed,0x6a,0x2},    // ECU 4
  {0x1b,0x28,0xde,0x9b,0xd6,0x9c,0xb4,0x6,0x77,0xf5,0x4f,0xb7,0xd4,0x15,0x78,0x76}   // ECU 5
};
uint8_t Pre_shared_key_y[6][16]={
  {0x33,0x69,0x92,0x70,0x1c,0x3a,0xad,0x5,0x75,0x5b,0x9b,0x64,0x3f,0x9b,0x72,0xbd},  // ECU 0
  {0xce,0xda,0x31,0x94,0x8e,0x39,0xdd,0x10,0x4a,0xe5,0xe4,0xfb,0xcd,0x2e,0x64,0x27}, // ECU 1
  {0x34,0xbb,0xf7,0x19,0x2b,0x85,0x28,0x90,0x53,0x7b,0x5f,0x6a,0x7e,0xbd,0xd6,0xfd}, // ECU 2
  {0x96,0xd7,0xd0,0x92,0x7,0x42,0xe4,0xca,0x28,0xb6,0xac,0x59,0x60,0xab,0xa9,0xa6},  // ECU 3
  {0xe,0x0,0x23,0xd2,0x1c,0x1f,0x14,0xff,0x73,0xf0,0x95,0xab,0x52,0xae,0x3,0x8b},    // ECU 4
  {0x31,0xcb,0x5c,0xe9,0x7,0xc4,0x4a,0xca,0x58,0xbd,0xfa,0xa0,0x77,0x4d,0x47,0xfd}   // ECU 5
};
  
  
uint8_t Session_key[M][16];

unsigned long EID[6]={0x001, 0x002, 0x003, 0x004, 0x005, 0x006}; // Within 8 bits
int counter[N];
int counterTT;

//Initialize time variable for elapse time calculation
double start0, start1, start2, endt0, endt1, endt2, elapsed0, elapsed1, elapsed2;

uint8_t auxX_All[6]={0xfc,0xf2,0xc3,0x07,0x13,0x48}; // Same aux x coordinate for every byte
uint8_t auxX[N];

uint8_t epoch[8]={0};
bool finished;

void array_assignment(uint8_t *array_1, uint8_t *array_2, uint8_t array_len)
{
  for(int i=0;i<array_len;i++)
  {
    array_1[i]=array_2[i];
  }
}

//Generate polynomials within GF_256
void Polynomial_generation(uint8_t Poly_para[M][N+1][16])
{
  RNG.begin("Polynomial_generation");
  RNG.rand(&Poly_para[0][0][0], M*(N+1)*16);
  for(int i=0;i<M;i++)
  {
    array_assignment(Session_key[i],Poly_para[i][0],16);
  }
}

void Session_key_generation()
{
  RNG.begin("Session_key_generation");
  RNG.rand(&Session_key[0][0], M*16);
}

// Send out PR_MSGs and KD_MSGs
void Key_distribution()
{ 
  uint8_t auxY[N][16];
  uint8_t R[N][16];
  uint8_t hmac[8];
  unsigned long ID;
  unsigned long MID;
  
  // Generate initial R
  RNG.rand(&R[0][0], N*16);

  // Send out PR_MSGs per ECU
  for(int i=0; i<N; i++)
  {
    ID = EID[i];
    hash.resetHMAC(Pre_shared_key_x[i], 16);
    hash.update(&ID, sizeof(ID));
    hash.update(epoch, 8);
    hash.update(&R[i][0], 16);
    hash.finalizeHMAC(Pre_shared_key_x[i], 16, hmac, 8);
    CAN.sendMsgBuf(ID, 1, 8, epoch);
//    Serial.print("epoch:\t");
//    for (int b = 0; b < 8; b++) 
//    {
//      Serial.print(epoch[b],HEX);
//      Serial.print("\t");
//    }
//    Serial.println();
//    delay(ArtDELAY);
    CAN.sendMsgBuf(ID, 1, 8, &R[i][0]);
//    Serial.print("R1:\t");
//    for (int b = 0; b < 8; b++) 
//    {
//      Serial.print(R[i][b],HEX);
//      Serial.print("\t");
//    }
//    Serial.println();
//    delay(ArtDELAY);
    CAN.sendMsgBuf(ID, 1, 8, &R[i][8]);
//    Serial.print("R2:\t");
//    for (int b = 8; b < 16; b++) 
//    {
//      Serial.print(R[i][b],HEX);
//      Serial.print("\t");
//    }
//    Serial.println();
//    delay(ArtDELAY);
    CAN.sendMsgBuf(ID, 1, 8, hmac);
//    Serial.print("hmac:\t");
//    for (int b = 0; b < 8; b++) 
//    {
//      Serial.print(hmac[b],HEX);
//      Serial.print("\t");
//    }
//    Serial.println();
//    delay(ArtDELAY);
  }

  start0 = micros();
  // Send out KD_MSGs per MID
  for(int m=0;m<M;m++){
    // Compute the Rs for this MID
    MID = m + 1;
    ID = 0x10000000 + MID; // CAN ID
    for(int n=0;n<N;n++){
      hash.reset();
      hash.update(&R[n][0], 16);
      hash.update(&MID, sizeof(MID));
      hash.finalize(&R[n][0], 16);
    }
    // Compute the aux y points
    for(int b=0;b<16;b++)
    { 
      uint8_t points_x[N+1];
      uint8_t points_y[N+1];
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
      
//      Serial.print(auxY[0][b], HEX);
//      Serial.print(" ");
    }

    // Compute hmac
    hash.resetHMAC(Session_key[m], 16);
    hash.update(&ID, sizeof(ID));
    hash.update(epoch, 8);
    hash.finalizeHMAC(Session_key[m], 16, hmac, 8);

    // Send out KD_MSG
    CAN.sendMsgBuf(ID, 1, 8, epoch);
    delay(ArtDELAY);
    for(int n=0;n<N;n++)
    {
      CAN.sendMsgBuf(ID, 1, 8, &auxY[n][0]);
      delay(ArtDELAY);
      CAN.sendMsgBuf(ID, 1, 8, &auxY[n][8]);
      delay(ArtDELAY);  
    }
    CAN.sendMsgBuf(ID, 1, 8, hmac);
  }
  endt0 = micros();
}

uint8_t Largrange_interpolation(uint8_t points_x[N+1], uint8_t points_y[N+1], uint8_t x_coordinate)
{
  uint8_t y_coordinate=0;
  for(int i=0;i<N+1;i++)
  {
    uint8_t tmp=0;
//    uint8_t tmp=1;
    for(int j=0;j<N+1;j++)
    {
      if(j!=i)
      {
//        tmp^=GF256_Exp[(GF256_Log[x_coordinate^points_x[j]]+GF256_Log[GF256_Inv[points_x[j]^points_x[i]]])%0xff];
//        tmp = ((tmp+GF256_Log[x_coordinate^points_x[j]])%0xff+GF256_Log[GF256_Inv[points_x[j]^points_x[i]]])%0xff;
        tmp = tmp + GF256_Log[x_coordinate^points_x[j]] + GF256_Log[GF256_Inv[points_x[j]^points_x[i]]];
      }
    }
//    y_coordinate ^= GF256_Exp[(GF256_Log[points_y[i]]+GF256_Log[tmp])%0xff];
//    y_coordinate ^= GF256_Exp[(GF256_Log[points_y[i]]+tmp)%0xff];
    y_coordinate ^= GF256_Exp[GF256_Log[points_y[i]] + tmp];
  }
  return y_coordinate;
}

/*
// Send out PRMSGs per ECU
void send_prmsg(uint8_t Poly_para[M][N+1][16], uint8_t Pre_shared_key_x[N][16], uint8_t Pre_shared_key_y[N][16],uint8_t epoch[8])
{
  uint8_t Rtmp[16];
  uint8_t hmac[8];

  for(int n=0;n<N;n++)
  {
    unsigned long ID = EID[n];
    
    Serial.print("------- Send PRMSG with ID: ");
    Serial.print(ID,HEX);
    Serial.print(" to node ");
    Serial.print(n);
    Serial.println(" -------");
    
    for(int k=0;k<16;k++)
    {
      Rtmp[k]=0;      
      for(int l=0;l<N+1;l++)
      {
        Rtmp[k]=Rtmp[k]^GF256_Exp[(GF256_Log[Poly_para[m][l][k]]+l*GF256_Log[Pre_shared_key_x[n][k]])%0xff];
      }   
      Rtmp[k]=Rtmp[k]^Pre_shared_key_y[n][k];  
    }
    
    hash.resetHMAC(Pre_shared_key_x[n], 16);
    hash.update(&ID, sizeof(ID));
    hash.update(epoch, 8);
    hash.update(Rtmp, 16);
    hash.finalizeHMAC(Pre_shared_key_x[n], 16, hmac, 8);
    
    CAN.sendMsgBuf(ID, 1, 8, epoch);
    Serial.print("epoch:\t");
    for (int i = 0; i < 8; i++) 
    {
      Serial.print(epoch[i],HEX);
      Serial.print("\t");
    }
    Serial.println();
    delay(ArtDELAY1);
    
    CAN.sendMsgBuf(ID, 1, 8, Rtmp);
    Serial.print("Rtmp1:\t");
    for (int i = 0; i < 8; i++) 
    {
      Serial.print(Rtmp[i],HEX);
      Serial.print("\t");
    }
    Serial.println();
    delay(ArtDELAY1);
    
    CAN.sendMsgBuf(ID, 1, 8, &Rtmp[8]);
    Serial.print("Rtmp2:\t");
    for (int i = 0; i < 8; i++) 
    {
      Serial.print(Rtmp[i+8],HEX);
      Serial.print("\t");
    }
    Serial.println();
    delay(ArtDELAY1);
    
    CAN.sendMsgBuf(ID, 1, 8, hmac);
    Serial.print("hmac:\t");
    for (int i = 0; i < 8; i++) 
    {
      Serial.print(hmac[i],HEX);
      Serial.print("\t");
    }
    Serial.println();
    delay(ArtDELAY);
   }
}

// Send out KDMSGs per MSG
void send_kdmsg(uint8_t Poly_para[M][N+1][16], uint8_t List[N], uint8_t epoch[8])
{
  unsigned long ID;
  uint8_t tmp_points[16];
  uint8_t hmac[8];
  for(int m=0;m<M;m++)
  {
    ID = MID + m;
    
    Serial.print("------- Broadcast KDMSG with ID: ");
    Serial.print(ID,HEX);
    Serial.println(" -------");
      
    CAN.sendMsgBuf(ID, 1, 8, epoch);
    Serial.print("epoch:\t");
    for (int i = 0; i < 8; i++) 
    {
      Serial.print(epoch[i],HEX);
      Serial.print("\t");
    }
    Serial.println();
    delay(200);
  
    for(int n=0;n<N-1;n++)
    {
      //Serial.println();
      //Serial.println("Print points:");
      for(int k=0;k<16;k++)
      {
        tmp_points[k]=0;
        for(int l=0;l<N+1;l++)
        {
          tmp_points[k]=tmp_points[k]^GF256_Exp[(GF256_Log[Poly_para[m][l][k]]+l*GF256_Log[List[n]])%0xff];
        }  
      }
//      hash.update(tmp_points, 16);
      CAN.sendMsgBuf(ID, 1, 8, tmp_points);
      Serial.print("pts1:\t");
      for (int i = 0; i < 8; i++) 
      {
        Serial.print(tmp_points[i],HEX);
        Serial.print("\t");
      }
      Serial.println();
      delay(ArtDELAY1);
      
      CAN.sendMsgBuf(ID, 1, 8, &tmp_points[8]);
      Serial.print("pts2:\t");
      for (int i = 0; i < 8; i++) 
      {
        Serial.print(tmp_points[i+8],HEX);
        Serial.print("\t");
      }
      Serial.println();
      delay(ArtDELAY1);      
    }

    // MAC of KDMSG: hash(session key|mid|epoch)
    hash.reset();
    hash.update(Session_key[m],16);
    hash.update(&ID, sizeof(ID));
    hash.update(epoch, 8);
    hash.finalize(hmac, 8);
    
    CAN.sendMsgBuf(ID, 1, 8, hmac);
    Serial.print("hmac:\t");
    for (int i = 0; i < 8; i++) 
    {
      Serial.print(hmac[i],HEX);
      Serial.print("\t");
    }
    Serial.println();
    delay(ArtDELAY);
  } 
}
*/
  
// Function for Hash checking on CO_MSG
uint8_t check_message_digest(unsigned long ID, uint8_t MAC[8], int e)
{
  uint8_t tmp_MAC[8];
  uint8_t tmp_flag = 0;
  hash.resetHMAC(Pre_shared_key_y[e], 16);
  hash.update(&ID, sizeof(ID));
  hash.update(epoch, 8);
  for(int j=0;j<M;j++)
  {
    hash.update(Session_key[j], 16);
  }
  hash.finalizeHMAC(Pre_shared_key_y[e], 16, tmp_MAC, 8);
 
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
  //init can bus : baudrate = 500k
  while (CAN_OK != CAN.begin(CAN_500KBPS)) {
      Serial.println("CAN BUS Shield init fail");
      Serial.println(" Init CAN BUS Shield again");
      delay(100);
  }
  Serial.println("CAN BUS Shield init ok!");
  Serial.print("SSKT Key Server. #N = ");
  Serial.println(N);

  finished = false;
  for(int n=0;n<N;n++)
  {
    auxX[n] = auxX_All[n];
  }
  
  for(int e=0;e<N;e++)
  {
    counter[e] = 0;
  }
  counterTT = 0;
  epoch[7]=1;
  elapsed0 = 0;
//  uint8_t Poly_para[M][N][16];
  
  start1 = micros();
//  Polynomial_generation(Poly_para);
  Session_key_generation();
  endt1 = micros();

  Serial.println();
  for(int m=0;m<M;m++)
  {
    Serial.println("Session key generated:");
    for(int b=0;b<16;b++)
    {
      Serial.print(Session_key[m][b], HEX);
      Serial.print(" ");
    }
    Serial.println();
  }
  start2= micros(); 
  Key_distribution();
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
    CAN.readMsgBuf(&len, buf); 

    if(!finished)
    {
      canId = CAN.getCanId();
      
//      Serial.println("-----------------------------");
//      Serial.print("get data from ID: 0x");
//      Serial.println(canId, HEX);
//      for (int i = 0; i < len; i++) 
//      {
//          Serial.print(buf[i],HEX);
//          Serial.print("\t");
//      }
//      Serial.println();

      // We explicitly list out the correspondence between (0x200+EID) and ECU index
      switch(canId)
      {
        case 0x201:
          ecu = 0;
          break;
        case 0x202:
          ecu = 1;
          break;
        case 0x203:
          ecu = 2;
          break;
        case 0x204:
          ecu = 3;
          break;
        case 0x205:
          ecu = 4;
          break;
        case 0x206:
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

      if(counterTT>=2*N)
      {
//        if(flag==1)
//        {
//         Serial.println();
//         Serial.println("Confirmation Fail");
//        }
//        else
        {
          endt2 = micros();
          finished = true;
          Serial.println();
          Serial.println("Confirmation Success");
          elapsed1= endt1 - start1;
          elapsed2= endt2 - start2;
          elapsed0= endt0 - start0;
          
          Serial.println();
          Serial.print("Time for key generation (ms): ");
          Serial.print(elapsed1/1000);
          Serial.println();
          Serial.print("Time for key distribution (ms): ");
          Serial.println(elapsed2/1000);
          Serial.print("Sum (ms): ");
          Serial.println((elapsed1+elapsed2)/1000);
          Serial.print("Time for sending all KDMSGs (ms): ");
          Serial.println(elapsed0/1000);
          Serial.println();
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
