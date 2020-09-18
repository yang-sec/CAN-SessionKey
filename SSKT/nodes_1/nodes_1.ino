//SKDC protocol, ECU nodes
//Shanghao Shi
//Protocol Implemention for ACSAC2020-Session key Distribution Make Practical for CAN and CAN-FD Message Authentication

#include <SPI.h>
#include "mcp_can.h"
#include <SHA256.h>
#include <GF256.h>

/* PLEASE CHANGE TO SEE DIFFERENT SETUPS */  
// Keep it the the same with the KS setup
const int M=1; // Number of MSG IDs. Please fix M=1.
const int N=2; // Number of normal ECUs with the max of 6. {2,3,4,5,6} are used in the paper. 
const int LocalN=1; // Number of normals simulated by the node

//Set CS pin
const int SPI_CS_PIN = 9;
MCP_CAN CAN(SPI_CS_PIN);
SHA256 hash;

int counter=0;
uint8_t Pre_shared_key_x[16]=
  {0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28};
uint8_t Pre_shared_key_y[16]=
  {0x33,0x69,0x92,0x70,0x1c,0x3a,0xad,0x5,0x75,0x5b,0x9b,0x64,0x3f,0x9b,0x72,0xbd};
  
unsigned long EID[3]={0x000800, 0x001800, 0x002800};
unsigned long MID=0x000101;

uint8_t ListTT[5]={0xFC,0xF1,0xCD,0x07,0x13};
uint8_t List[N-1];

uint8_t flag;
uint8_t epoch[8]={0,0,0,0,0,0,0,0};
uint8_t R[LocalN][16];
uint8_t Session_key[LocalN][16];
uint8_t Pre_computed_list[M][N][16];

uint8_t ECU1_counter=0;
uint8_t ECU2_counter=0;
uint8_t ECU3_counter=0;
uint8_t points_counter=0;
    
	
void array_assignment(uint8_t *array_1, uint8_t *array_2, uint8_t array_len){
  for(int i=0;i<array_len;i++){
    array_1[i]=array_2[i];
    }
  }

uint8_t check_hmac(uint8_t new_hmac[8], unsigned long ID, uint8_t tmp_epoch[8], uint8_t R[16], uint8_t key[16])
{
  uint8_t tmp_hmac[8];
  hash.resetHMAC(key, 16);
  hash.update(&ID, sizeof(ID));
  hash.update(tmp_epoch, 8);
  hash.update(R, 16);
  hash.finalizeHMAC(key, 16, tmp_hmac, 8);
  for(int i=0;i<8;i++)
  {
    if(tmp_hmac[i]!=new_hmac[i])
    {
      Serial.println("Secret MAC does not match");
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
  for(int i=0;i<M;i++)
  {
    for(int j=0;j<N;j++)
    {
      Serial.println("Pre_computed_list:");
      for(int k=0;k<16;k++)
      {
        New_list[N-1]=Pre_shared_key_x[k];
        Pre_computed_list[i][j][k]=0;
        for(int l=0;l<N;l++)
        {
          if(l!=j)
          {
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

uint8_t recover_session_key(
  uint8_t Pre_computed_list[N][16], 
  uint8_t Pre_shared_secret_y[16], 
  uint8_t R[16], 
  uint8_t points[N-1][16], 
  unsigned long can_ID, 
  uint8_t epoch[8],
  uint8_t MAC[8],
  uint8_t Session_key[16])
{
  uint8_t New_MAC[8];
  
  for(int i=0;i<16;i++)
  {
    // Interpolation with pre-computed Lagrange coeffs
    Session_key[i]=0;
    for(int j=0;j<N;j++)
    {
      if(j!=(N-1))
      {
        Session_key[i]=Session_key[i]^GF256_Exp[(GF256_Log[points[j][i]]+GF256_Log[Pre_computed_list[j][i]])%0xff];
      }
      else
      {
        Session_key[i]=Session_key[i]^GF256_Exp[(GF256_Log[Pre_shared_secret_y[i]^R[i]]+GF256_Log[Pre_computed_list[j][i]])%0xff];
      }
    }
  }

  // Check MAC. MAC of KDMSG: hash(session key|mid|epoch)
  hash.reset();
  hash.update(Session_key, 16);
  hash.update(&can_ID, sizeof(can_ID));
  hash.update(epoch, 8);
  hash.finalize(New_MAC,8);
  for(int b=0;b<8;b++)
  {
    if(New_MAC[b]!=MAC[b])
    {
      Serial.println("KDMSG MAC not check");
      return 1;
    }
  }
  return 0;
}

void send_message_back(uint8_t flag, uint8_t Session_key[16], uint8_t epoch[8], int e)
{
  uint8_t MAC[8];
  unsigned long re_ID = 0x010000 + EID[e];
  hash.reset();
  hash.update(&re_ID, 4);

  hash.update(epoch, 8);
//  Serial.println();
  
  if(flag==0)
  {
//    for(int s=0; s<M; s++)
//    {
//      hash.update(Session_key[s], 16);
//    }
    hash.update(Session_key, 16);
    
    hash.finalize(MAC,8);
    CAN.sendMsgBuf(re_ID, 1, 8, epoch);
    CAN.sendMsgBuf(re_ID, 1, 8, MAC);
  }
  else
  {
    hash.finalize(MAC,8);
    CAN.sendMsgBuf(re_ID, 1, 8, epoch);
    CAN.sendMsgBuf(re_ID, 1, 8, MAC);
  }
}

void setup() {
    Serial.begin(115200);

    while (CAN_OK != CAN.begin(CAN_500KBPS)) {            // init can bus : baudrate = 500k
        Serial.println("CAN BUS Shield init fail");
        Serial.println("Init CAN BUS Shield again");
        delay(100);
    }
	//Initilize Masks and Filters
	//Different ECU nodes need different Masks and Filters initilization to receive different message
    CAN.init_Mask(0, 1, 0x1fffffff);
    CAN.init_Mask(1, 1, 0x1fffffff);
    CAN.init_Filt(0, 1, MID); // The MID for KDMSG
    CAN.init_Filt(1, 1, EID[0]+1); // For PRMSG
    CAN.init_Filt(2, 1, EID[1]+1);
    CAN.init_Filt(3, 1, EID[2]+1);
    Serial.println("CAN BUS Shield init ok!");
    Serial.println();

    for(int e=0;e<N-1;e++)
    {
      List[e] = ListTT[e];
    }
    
    epoch[7]=1;
    pre_compute();
    counter=0;  
}

void loop() {
    uint8_t len = 8;
    uint8_t buf[8];
    unsigned long canId;

    if (CAN_MSGAVAIL == CAN.checkReceive()) // check if data coming
    {
        CAN.readMsgBuf(&len, buf);    // read data
        canId = CAN.getCanId();

        Serial.print("------- Get data from ID: 0x");
        Serial.println(canId, HEX);
//        for (int i = 0; i < len; i++) // print the data
//        { 
//            Serial.print(buf[i],HEX);
//            Serial.print("\t");
//        }
        Serial.println();
		
		switch(canId){
			case 0x000101:
				uint8_t points[N-1][16];
				uint8_t MAC[8];
				if(points_counter==0)
				{
					uint8_t tmp_epoch[8];
					array_assignment(tmp_epoch,buf,8);
					if(tmp_epoch[7]!=epoch[7])
					{
						flag=1;
					}
				}
				for(int k=0;k<N-1;k++){
					if(points_counter==2*k+1){
						array_assignment(points[k],buf,8);
					}
					else if(points_counter==2*k+2){
						array_assignment(&points[k][8],buf,8);
					}
				}
				if(points_counter==2*(N-1)+1){
					array_assignment(MAC,buf,8);
					flag=recover_session_key(Pre_computed_list[0], Pre_shared_key_y, R[0], points, canId, epoch, MAC, Session_key[0]);
				}

        if(points_counter < 2*N)
        {
          points_counter++;
        }
				break;
			case 0x000801:
				if(ECU1_counter==0){
					uint8_t tmp_epoch[8];
					array_assignment(tmp_epoch,buf,8);
					if(tmp_epoch[7]!=epoch[7])
					{
						flag=1;
					}
					ECU1_counter++;	
				}
				else if(ECU1_counter==1){
					array_assignment(R[0],buf,8);
					ECU1_counter++;
				}
				else if(ECU1_counter==2){
					array_assignment(&R[0][8],buf,8);
					ECU1_counter++;
				}
				else if(ECU1_counter==3){
					uint8_t new_hmac[8];
					array_assignment(new_hmac,buf,8);
					flag=check_hmac(new_hmac,canId,epoch,R[0],Pre_shared_key_x);
				}
				break;
			case 0x001801:
				if(ECU2_counter==0){
					uint8_t tmp_epoch[8];
					array_assignment(tmp_epoch,buf,8);
					if(tmp_epoch[7]!=epoch[7])
					{
						flag=1;
					}
					ECU2_counter++;	
				}
				else if(ECU2_counter==1){
					array_assignment(R[1],buf,8);
					ECU2_counter++;
				}
				else if(ECU2_counter==2){
					array_assignment(&R[1][8],buf,8);
					ECU2_counter++;
				}
				else if(ECU2_counter==3){
					uint8_t new_hmac[8];
					array_assignment(new_hmac,buf,8);
					flag=check_hmac(new_hmac,canId,epoch,R[1],Pre_shared_key_x);
				}
				break;
			case 0x002801:
				if(ECU3_counter==0){
					uint8_t tmp_epoch[8];
					array_assignment(tmp_epoch,buf,8);
					if(tmp_epoch[7]!=epoch[7])
					{
						flag=1;
					}
					ECU3_counter++;	
				}
				else if(ECU3_counter==1){
					array_assignment(R[2],buf,8);
					ECU3_counter++;
				}
				else if(ECU3_counter==2){
					array_assignment(&R[2][8],buf,8);
					ECU3_counter++;
				}
				else if(ECU3_counter==3){
					uint8_t new_hmac[8];
					array_assignment(new_hmac,buf,8);
					flag=check_hmac(new_hmac,canId,epoch,R[2],Pre_shared_key_x);
				}
				break;
		}
      counter++;
      Serial.print("counter = ");
      Serial.println(counter);
      
      if(counter==4*LocalN+2*(N-1)+1+1)
      {
        for(int repeat=0;repeat<7;repeat++)
        {	
    			for(int i=0;i<LocalN;i++)
    			{
    			  send_message_back(flag,Session_key[i],epoch,i);
    			  delay(3);
    			}
        }

        for(int e=0;e<LocalN;e++)
        {
          Serial.println("Session key obtained:\t");
          for(int b=0;b<16;b++)
          {
            Serial.print(Session_key[e][b], HEX);
            Serial.print("\t");
          }
          Serial.println();
        }

        points_counter = 0;
        ECU1_counter = 0;
        ECU2_counter = 0;
        ECU3_counter = 0;
        counter = 0;
      }
    }
}

//END FILE
