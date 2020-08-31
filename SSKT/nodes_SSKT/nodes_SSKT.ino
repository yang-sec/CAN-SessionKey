//SKDC protocol, ECU nodes
//Shanghao Shi
//Protocol Implemention for ACSAC2020-Session key Distribution Make Practical for CAN and CAN-FD Message Authentication

#include <SPI.h>
#include "mcp_can.h"
#include <SHA256.h>
#include <GF256.h>

/* PLEASE CHANGE TO SEE DIFFERENT SETUPS */
// Keep it the the same with the KS setup
const int M=1; // Number of MSG IDs. M=1 is used in the paper
const int N=2; // Number of normal ECUs with the max of 6. {2,3,4,5,6} are used in the paper. 

//Set CS pin
const int SPI_CS_PIN = 9;
MCP_CAN CAN(SPI_CS_PIN);
SHA256 hash;

int counter=0;
uint8_t Pre_shared_key_x[16]={0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
uint8_t Pre_shared_key_y[16]={0x11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
uint8_t flag;
uint8_t epoch[8]={0,0,0,0,0,0,0,0};
uint8_t R[M][16];
uint8_t Session_key[M][16];
uint8_t List[N-1]={0xFC};
uint8_t Pre_computed_list[M][N][16];
                    
void array_assignment(uint8_t *array_1, uint8_t *array_2, uint8_t array_len){
  for(int i=0;i<array_len;i++){
    array_1[i]=array_2[i];
    }
  }

uint8_t check_hmac(uint8_t new_hmac[8], unsigned long ID, uint8_t tmp_epoch[8], uint8_t R[16], uint8_t key[16]){
  uint8_t tmp_hmac[8];
  hash.resetHMAC(key, 16);
  hash.update(&ID, sizeof(ID));
  hash.update(tmp_epoch, 8);
  hash.update(R, 16);
  hash.finalizeHMAC(key, 16, tmp_hmac, 8);
  Serial.println("hmac");
  for(int i=0;i<8;i++){
    Serial.print(tmp_hmac[i]);
    Serial.print("\t");
    if(tmp_hmac[i]!=new_hmac[i]){
      return 1;
      break;
      }
    }
  Serial.println();
  return 0;
  }

//Precompute process
//This part is done during CAN bus setup process, computation overhead can be significantly reduced
//Details can be found in the paper
void pre_compute(){
  uint8_t New_list[N];
  array_assignment(New_list, List, N-1);
  for(int i=0;i<M;i++){
    for(int j=0;j<N;j++){
      Serial.println("Pre_computed_list:");
      for(int k=0;k<16;k++){
        New_list[N-1]=Pre_shared_key_x[k];
        Pre_computed_list[i][j][k]=0;
        for(int l=0;l<N;l++){
          if(l!=j){
            Pre_computed_list[i][j][k]=((Pre_computed_list[i][j][k]+GF256_Log[New_list[l]])%0xff+GF256_Log[GF256_Inv[New_list[j]^New_list[l]]])%0xff;//delete 0x01
          }
          }
        Pre_computed_list[i][j][k]=GF256_Exp[Pre_computed_list[i][j][k]];
        Serial.print(Pre_computed_list[i][j][k],HEX);
        Serial.print("\t");
        }  
      Serial.println();    
      }        
    }
  
  }

void recover_session_key(uint8_t Pre_computed_list[N][16], uint8_t Pre_shared_secret_y[16], uint8_t R[16], uint8_t points[N-1][16], uint8_t Session_key[16]){
  for(int i=0;i<16;i++){
    Session_key[i]=0;
    for(int j=0;j<N;j++){
      if(j!=(N-1)){
      Session_key[i]=Session_key[i]^GF256_Exp[(GF256_Log[points[j][i]]+GF256_Log[Pre_computed_list[j][i]])%0xff];
      }
      else{
      Session_key[i]=Session_key[i]^GF256_Exp[(GF256_Log[Pre_shared_secret_y[i]^R[i]]+GF256_Log[Pre_computed_list[j][i]])%0xff];
      }
      }
  }
}

void send_message_back(uint8_t flag, uint8_t Session_key[M][16], uint8_t epoch[8]){
  uint8_t MAC[8];
  unsigned long re_ID=0x080000;
  hash.reset();
  hash.update(&re_ID, 4);
  for(int l=0;l<8;l++){
  Serial.println(epoch[l]);}
  hash.update(epoch, 8);
  if(flag==0){
    for(int s=0; s<M; s++){
      Serial.println("Session key:");
      for(int l=0;l<16;l++){
          Serial.print(Session_key[s][l]);
          Serial.println("\t");
        }
    hash.update(Session_key[s], 16);
    }
    hash.finalize(MAC,8);
    CAN.sendMsgBuf(re_ID, 1, 8, epoch);
    //delay(200);
    CAN.sendMsgBuf(re_ID, 1, 8, MAC);
    }
  else{
    hash.finalize(MAC,8);
    CAN.sendMsgBuf(re_ID, 1, 8, epoch);
    //delay(200);
    CAN.sendMsgBuf(re_ID, 1, 8, MAC);
    }
  }


uint8_t check_MAC(unsigned long can_ID, uint8_t epoch[8], uint8_t points[N-1][16], uint8_t MAC[8]){
  uint8_t New_MAC[8];
  hash.reset();
  hash.update(&can_ID, sizeof(can_ID));
  hash.update(epoch, 8);
  for(int i=0;i<N-1; i++){
    hash.update(points[i], 16);
    }
  hash.finalize(New_MAC,8);
  for(int i=0;i<8;i++){
    if(New_MAC[i]!=MAC[i]){
      return 1;
      }
    }
  return 0;
  }

void setup() {
    Serial.begin(9600);

    while (CAN_OK != CAN.begin(CAN_500KBPS)) {            // init can bus : baudrate = 500k
        Serial.println("CAN BUS Shield init fail");
        Serial.println("Init CAN BUS Shield again");
        delay(100);
    }
	//Initilize Masks and Filters
	//Different ECU nodes need different Masks and Filters initilization to receive different message
    CAN.init_Mask(0, 1, 0x1fffffff);
    CAN.init_Mask(1, 1, 0x1fffffff);
    CAN.init_Filt(0, 1, 0x01);
    CAN.init_Filt(1, 1, 0x080001);
    Serial.println("CAN BUS Shield init ok!");
    epoch[7]=1;
    pre_compute();
    Serial.println("epoch");
    for(int i=0;i<8;i++){
      Serial.print(epoch[i]);
      Serial.print("\t");
      }
    Serial.println();
    counter=0;  
}

void loop() {
    uint8_t len = 8;
    uint8_t buf[8];
    unsigned long canId;
    if (CAN_MSGAVAIL == CAN.checkReceive()) {// check if data coming
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
        for(int i=0;i<M;i++){
          if(counter==4*i+0){
           uint8_t tmp_epoch[8];
           array_assignment(tmp_epoch,buf,8);
           if(tmp_epoch[7]!=epoch[7]){
               flag=1;
            }
           }
          else if(counter==4*i+1){
           array_assignment(R[i],buf,8);
            }
          else if(counter==4*i+2){
           array_assignment(&R[i][8],buf,8);
           }
          else if(counter==4*i+3){
           uint8_t new_hmac[8];
           array_assignment(new_hmac,buf,8);
           flag=check_hmac(new_hmac,canId,epoch,R[i],Pre_shared_key_x);
           Serial.println("R:");
           for(int m=0;m<16;m++){
            Serial.print(R[i][m]);
            Serial.print("\t");
           }
            Serial.println();
            }
        }
        
        for(int j=0;j<M;j++){
          uint8_t points[N-1][16];
          uint8_t MAC[8];
          
          if(counter==4*M-1+1+2*N*j){
            uint8_t tmp_epoch[8];
            array_assignment(tmp_epoch,buf,8);
            if(tmp_epoch[7]!=epoch[7]){
                flag=1;
               }
            }
          
          for(int k=0;k<N-1;k++){
            if(counter==4*M+1+2*k+2*N*j){
              array_assignment(points[k],buf,8);
              }
            if(counter==4*M+2+2*k+2*N*j){
              array_assignment(&points[k][8],buf,8);
              }
            }
          
          if(counter==4*M+2*N-1+2*N*j){
            array_assignment(MAC,buf,8);
            flag=check_MAC(canId, epoch, points, MAC);
            recover_session_key(Pre_computed_list[j], Pre_shared_key_y, R[j], points, Session_key[j]);
            Serial.println();
            for(int s=0;s<16;s++){
              Serial.print(Session_key[j][s],HEX);
              Serial.print("\t");
              }
            Serial.println();
            }
          }
      Serial.println("counter:");
      Serial.println(counter);
      counter++;
      if(counter==4*M+2*N+2*N*(M-1)){
        send_message_back(flag,Session_key,epoch);
        counter=0;}
      Serial.println(flag);
    }
}

//END FILE
