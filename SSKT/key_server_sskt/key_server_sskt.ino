//SKDC protocol, Key Server
//Shanghao Shi
//Protocol Implemention for ACSAC2020-Session key Distribution Make Practical for CAN and CAN-FD Message Authentication

#include <mcp_can.h>
#include <SPI.h>
#include <SHA256.h>
#include <GF256.h>
#include <RNG.h>
//#include <TransistorNoiseSource.h>
#include <Crypto.h>

SHA256 hash;

//Set CS pin
const int SPI_CS_PIN = 9;
MCP_CAN CAN(SPI_CS_PIN);

/* PLEASE CHANGE TO SEE DIFFERENT SETUPS */
const int M=1; // Number of MSG IDs. Please fix M=1.
const int N=2; // Number of normal ECUs with the max of 6. {2,3,4,5,6} are used in the paper. 

const int ArtDELAY = 50; // Artifitial delay  


uint8_t Pre_shared_key_x[N][16]={
  {0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28},
  {0x2c,0xeb,0x89,0x11,0x5e,0x74,0xe6,0xd8,0xf6,0x8d,0xe2,0x33,0xad,0xb7,0x7b,0x4f}};
uint8_t Pre_shared_key_y[N][16]={
  {0x33,0x69,0x92,0x70,0x1c,0x3a,0xad,0x5,0x75,0x5b,0x9b,0x64,0x3f,0x9b,0x72,0xbd},
  {0xce,0xda,0x31,0x94,0x8e,0x39,0xdd,0x10,0x4a,0xe5,0xe4,0xfb,0xcd,0x2e,0x64,0x27}};
uint8_t Session_key[M][16];

unsigned long EID[6]={0x000800, 0x001000, 0x001800, 0x002000, 0x002800, 0x003000};
unsigned long MID=0x000101; // To start from 0x000101, the plus 1, ...
int counter[N];
int counterTT;

//Initialize time variable for elapse time calculation
double start0, start1, start2, end0, endt1, endt2, elapsed0, elapsed1, elapsed2;

//List of x coordinate of broadcast points
uint8_t List[N-1]={0xFC};

uint8_t epoch[8]={0,0,0,0,0,0,0,0};
//int counter=0;
bool finished;

void array_assignment(uint8_t *array_1, uint8_t *array_2, uint8_t array_len){
  for(int i=0;i<array_len;i++){
    array_1[i]=array_2[i];
    }
  }

//Generate polynomials within GF_256
void Polynomial_generation(uint8_t Poly_para[M][N][16])
{
  RNG.begin("Polynomial_generation");
  RNG.rand(&Poly_para[0][0][0], M*N*16);
  for(int i=0;i<M;i++)
  {
    array_assignment(Session_key[i],Poly_para[i][0],16);
  }
}

//Generate and send random chanllenge via CAN bus
//Time delays are added to let CAN bus work more smoothly
void Random_challenge(uint8_t Poly_para[M][N][16], uint8_t Pre_shared_key_x[N][16], uint8_t Pre_shared_key_y[N][16],uint8_t epoch[8]){
  uint8_t Rtmp[16];
  uint8_t hmac[8];
  for(int m=0;m<M;m++)
  {
    for(int n=0;n<N;n++)
    {
      unsigned long ID = EID[n] + m + 1;
      
//      Serial.print("------- Send PRMSG with ID: ");
//      Serial.print(ID,HEX);
//      Serial.print(" to node ");
//      Serial.print(n);
//      Serial.println(" -------");
      
      for(int k=0;k<16;k++)
      {
        Rtmp[k]=0;      
        for(int l=0;l<N;l++)
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
//      Serial.print("epoch:\t");
//      for (int i = 0; i < 8; i++) 
//      {
//        Serial.print(epoch[i],HEX);
//        Serial.print("\t");
//      }
//      Serial.println();
//      delay(200);
      
      CAN.sendMsgBuf(ID, 1, 8, Rtmp);
//      Serial.print("Rtmp1:\t");
//      for (int i = 0; i < 8; i++) 
//      {
//        Serial.print(Rtmp[i],HEX);
//        Serial.print("\t");
//      }
//      Serial.println();
//      delay(200);
      
      CAN.sendMsgBuf(ID, 1, 8, &Rtmp[8]);
//      Serial.print("Rtmp2:\t");
//      for (int i = 0; i < 8; i++) 
//      {
//        Serial.print(Rtmp[i+8],HEX);
//        Serial.print("\t");
//      }
//      Serial.println();
//      delay(200);
      
      CAN.sendMsgBuf(ID, 1, 8, hmac);
//      Serial.print("hmac:\t");
//      for (int i = 0; i < 8; i++) 
//      {
//        Serial.print(hmac[i],HEX);
//        Serial.print("\t");
//      }
//      Serial.println();
      delay(ArtDELAY);
     }
   }
}

//Generate and broadcast points on the polynomials
void points(uint8_t Poly_para[M][N][16], uint8_t List[N-1], uint8_t epoch[8]){
  unsigned long ID=0x00000000;
  uint8_t tmp_points[16];
  uint8_t hmac[8];
  for(int m=0;m<M;m++){
//    ID=ID+1;
    ID = MID + m;

//    Serial.print("------- Broadcast KDMSG with ID: ");
//    Serial.print(ID,HEX);
//    Serial.println(" -------");
      
    CAN.sendMsgBuf(ID, 1, 8, epoch);
//    Serial.print("epoch:\t");
//    for (int i = 0; i < 8; i++) 
//    {
//      Serial.print(epoch[i],HEX);
//      Serial.print("\t");
//    }
//    Serial.println();
//    delay(200);

    
     
    for(int n=0;n<N-1;n++)
    {
      //Serial.println();
      //Serial.println("Print points:");
      for(int k=0;k<16;k++)
      {
        tmp_points[k]=0;
        for(int l=0;l<N;l++)
        {
          tmp_points[k]=tmp_points[k]^GF256_Exp[(GF256_Log[Poly_para[m][l][k]]+l*GF256_Log[List[n]])%0xff];
        }  
      }
//      hash.update(tmp_points, 16);
      CAN.sendMsgBuf(ID, 1, 8, tmp_points);
//      Serial.print("pts1:\t");
//      for (int i = 0; i < 8; i++) 
//      {
//        Serial.print(tmp_points[i],HEX);
//        Serial.print("\t");
//      }
//      Serial.println();
//      delay(200);
      
      CAN.sendMsgBuf(ID, 1, 8, &tmp_points[8]);
//      Serial.print("pts2:\t");
//      for (int i = 0; i < 8; i++) 
//      {
//        Serial.print(tmp_points[i+8],HEX);
//        Serial.print("\t");
//      }
//      Serial.println();
//      delay(500);      
    }

    // MAC of KDMSG: hash(session key|mid|epoch)
    hash.reset();
    hash.update(Session_key[m],16);
    hash.update(&ID, sizeof(ID));
    hash.update(epoch, 8);
    hash.finalize(hmac, 8);
    
    CAN.sendMsgBuf(ID, 1, 8, hmac);
//    Serial.print("hmac:\t");
//    for (int i = 0; i < 8; i++) 
//    {
//      Serial.print(hmac[i],HEX);
//      Serial.print("\t");
//    }
//    Serial.println();
    delay(ArtDELAY);
  } 
}
  
//Check data integrity
void MAC_check(unsigned long ID, uint8_t new_MAC[8], uint8_t tmp_epoch[8]){
  uint8_t flag=0;
  uint8_t MAC[8];
  hash.reset();
  Serial.print("Receive COMSG from EID: 0x");
  Serial.println(ID-0x010000,HEX);
  hash.update(&ID, 4);
  hash.update(tmp_epoch, 8);
  for(int s=0; s<M; s++){
    hash.update(Session_key[s], 16);
    }
  hash.finalize(MAC,8);
  for(int i=0;i<8;i++){
    if(MAC[i]!=new_MAC[i]){
      flag=1;
      }
    }
//  if(flag==1){
//    Serial.println(" - MAC Check Fail");
//    }
//  else{
//    Serial.println(" - MAC Check Success");
//    }
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
  Serial.print("N = ");
  Serial.println(N);

  finished = false;
  for(int e=0;e<N;e++)
  {
    counter[e] = 0;
  }
  counterTT = 0;
  epoch[7]=1;
  elapsed0 = 0;
  uint8_t Poly_para[M][N][16];
  
  start1 = micros();
  Polynomial_generation(Poly_para);
  endt1 = micros();
  
  for(int m=0;m<M;m++)
  {
    Serial.println("Session key generated:");
    for(int b=0;b<16;b++)
    {
      Serial.print(Session_key[m][b], HEX);
      Serial.print("\t");
    }
    Serial.println();
  }
  Serial.println();
   
  start2= micros(); 
  // Send out PR_MSGs
  Random_challenge(Poly_para,Pre_shared_key_x,Pre_shared_key_y,epoch);
  // Send out KD_MSGs
  start0 = micros();
  points(Poly_para, List,epoch);
  elapsed0 += micros() - start0;
}

void loop() {
  uint8_t len = 8;
  uint8_t buf[8];
  unsigned long canId;
  uint8_t new_epoch[8];
  uint8_t new_MAC[8];
  int ecu;
  
  if (CAN_MSGAVAIL == CAN.checkReceive()) 
  {         
    CAN.readMsgBuf(&len, buf); 

    if(!finished)
    {
      canId = CAN.getCanId();
      
  //    Serial.println("-----------------------------");
  //    Serial.print("get data from ID: 0x");
  //    Serial.println(canId, HEX);
  //    for (int i = 0; i < len; i++) 
  //    {
  //        Serial.print(buf[i],HEX);
  //        Serial.print("\t");
  //    }
  //    Serial.println();
  
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
          array_assignment(new_epoch, buf, 8);
          break; 
        case 1:
          array_assignment(new_MAC, buf, 8);
          MAC_check(canId, new_MAC, epoch);
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
      
      
  //    for(int i=0;i<N;i++)
  //    {
  //      uint8_t new_MAC[8];
  //      if(counter==2*i)
  //      {
  //        array_assignment(new_epoch,buf,8);
  //      }
  //      else if(counter==2*i+1)
  //      {
  //        array_assignment(new_MAC,buf,8);
  //        MAC_check(canId,new_MAC,epoch);
  //      }
  //    }
          
  //    counter++;
      if(counterTT>=2*N)
      {
  //      counter=0;
        endt2 = micros();
  
        finished = true;
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
        Serial.println(elapsed0 - ArtDELAY*1000*M);
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
