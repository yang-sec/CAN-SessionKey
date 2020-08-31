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

//M is the number of Session key
//N is the number of ECU nodes
//M N can be changed
const int M=1;
const int N=2;

double start1, start2, endt1, endt2, elapsed1, elapsed2;

uint8_t Pre_shared_key_x[N][16]={{0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
{0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}};
uint8_t Pre_shared_key_y[N][16]={{0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
{0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}};
uint8_t Session_key[M][16];

//List of x coordinate of broadcast points
uint8_t List[N-1]={0xFC};

uint8_t epoch[8]={0,0,0,0,0,0,0,0};
int counter=0;

void array_assignment(uint8_t *array_1, uint8_t *array_2, uint8_t array_len){
  for(int i=0;i<array_len;i++){
    array_1[i]=array_2[i];
    }
  }

//Generate polynomials within GF_256
void Polynomial_generation(uint8_t Poly_para[M][N][16]){
  RNG.begin("Polynomial_generation");
  RNG.rand(&Poly_para[0][0][0], M*N*16);
  for(int i=0;i<M;i++){
    array_assignment(Session_key[i],Poly_para[i][0],16);
    }
  }

//Generate and send random chanllenge via CAN bus
//Time delays are added to let CAN bus work more smoothly
void Random_challenge(uint8_t Poly_para[M][N][16], uint8_t Pre_shared_key_x[N][16], uint8_t Pre_shared_key_y[N][16],uint8_t epoch[8]){
  uint8_t Rtmp[16];
  uint8_t hmac[8];
  for(int i=0;i<M;i++){
    for(int j=0;j<N;j++){
      for(int k=0;k<16;k++){
        Rtmp[k]=0;      
        for(int l=0;l<N;l++){
          Rtmp[k]=Rtmp[k]^GF256_Exp[(GF256_Log[Poly_para[i][l][k]]+l*GF256_Log[Pre_shared_key_x[j][k]])%0xff];
         }   
        Rtmp[k]=Rtmp[k]^Pre_shared_key_y[j][k];  
       } 
      unsigned long ID=0x00080000*(i+1)+(j+1);
      hash.resetHMAC(Pre_shared_key_x[j], 16);
      hash.update(&ID, sizeof(ID));
      hash.update(epoch, 8);
      hash.update(Rtmp, 16);
      hash.finalizeHMAC(Pre_shared_key_x[j], 16, hmac, 8);
      CAN.sendMsgBuf(ID, 1, 8, epoch);
      delay(200);
      CAN.sendMsgBuf(ID, 1, 8, Rtmp);
      delay(200);
      CAN.sendMsgBuf(ID, 1, 8, &Rtmp[8]);
      delay(200);
      CAN.sendMsgBuf(ID, 1, 8, hmac);
      delay(200);
     }
   }
  }

//Generate and broadcast points on the polynomials
void points(uint8_t Poly_para[M][N][16], uint8_t List[N-1], uint8_t epoch[8]){
  unsigned long ID=0x00000000;
  uint8_t tmp_points[16];
  uint8_t hmac[8];
  for(int i=0;i<M;i++){
    ID=ID+1;
    CAN.sendMsgBuf(ID, 1, 8, epoch);
    delay(200);
    hash.reset();
    hash.update(&ID, sizeof(ID));
    hash.update(epoch, 8);
    delay(1); 
    for(int j=0;j<N-1;j++){
      //Serial.println();
      //Serial.println("Print points:");
      for(int k=0;k<16;k++){
        tmp_points[k]=0;
        for(int l=0;l<N;l++){
          tmp_points[k]=tmp_points[k]^GF256_Exp[(GF256_Log[Poly_para[i][l][k]]+l*GF256_Log[List[j]])%0xff];
         }  
       }
      hash.update(tmp_points, 16);
      CAN.sendMsgBuf(ID, 1, 8, tmp_points);
      Serial.print(tmp_points[0],HEX);
      delay(200);
      CAN.sendMsgBuf(ID, 1, 8, &tmp_points[8]);
      Serial.print(tmp_points[8],HEX);
      delay(500);      
     }
     hash.finalize(hmac, 8);
     CAN.sendMsgBuf(ID, 1, 8, hmac);
   } 
  }
  
//Check data integrity
void MAC_check(unsigned long ID, uint8_t new_MAC[8], uint8_t tmp_epoch[8]){
  uint8_t flag=0;
  uint8_t MAC[8];
  hash.reset();
  Serial.println("ID:");
  Serial.println(ID);
  hash.update(&ID, 4);
  Serial.println("tmp_epoch:");
    for(int l=0;l<8;l++){
      Serial.print(tmp_epoch[l]);
      Serial.print("\t");
      }
  hash.update(tmp_epoch, 8);
  for(int s=0; s<M; s++){
    hash.update(Session_key[s], 16);
    Serial.println("tmp_epoch:");
    for(int l=0;l<16;l++){
      Serial.print(Session_key[s][l]);
      Serial.print("\t");
      }}
  hash.finalize(MAC,8);
  for(int i=0;i<8;i++){
    if(MAC[i]!=new_MAC[i]){
      flag=1;
      }
    }
  Serial.println();
  if(flag==1){
    Serial.println("Fail");
    }
  else{
    Serial.println("Success");
    }
  }

void setup(){
   Serial.begin(9600);
   //init can bus : baudrate = 500k
   while (CAN_OK != CAN.begin(CAN_500KBPS)) {
        Serial.println("CAN BUS Shield init fail");
        Serial.println(" Init CAN BUS Shield again");
        delay(100);
   }
   Serial.println("CAN BUS Shield init ok!");
   Serial.println("sasasasasasa");
   start1 = micros();
   epoch[7]=1;
   uint8_t Poly_para [M][N][16];
   Polynomial_generation(Poly_para);
   Random_challenge(Poly_para,Pre_shared_key_x,Pre_shared_key_y,epoch);
   points(Poly_para, List,epoch);
    counter=0;
    endt1 = micros();
}

void loop() {
  start2= micros();
  uint8_t len = 8;
  uint8_t buf[8];
  unsigned long canId;
  uint8_t new_epoch[8];
  if (CAN_MSGAVAIL == CAN.checkReceive()) {         // check if data coming
      CAN.readMsgBuf(&len, buf);    // read data

      canId = CAN.getCanId();
      Serial.println("-----------------------------");
      Serial.println("get data from ID: 0x");
      Serial.println(canId, HEX);
      for (int i = 0; i < len; i++) { // print the data
          Serial.print(buf[i],HEX);
          Serial.print("\t");
      }
      Serial.println();
      for(int i=0;i<1;i++){//N
        uint8_t new_MAC[8];
        if(counter==2*i){
          array_assignment(new_epoch,buf,8);
          }
        else if(counter==2*i+1){
          array_assignment(new_MAC,buf,8);
          MAC_check(canId,new_MAC,epoch);
          }
        }
  counter++;
  if(counter==2*N){counter=0;
   endt2 = micros();
        elapsed1= endt1 - start1;
        elapsed2= endt2 - start2;
        Serial.println("Elapsed time:");
        Serial.println(elapsed1);
        Serial.println(elapsed2);
		//Protocol execution time = elapsed1 + elapsed2 - added time delay
		}
  }
  
}
