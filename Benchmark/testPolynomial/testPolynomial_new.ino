/* Benchmarking the runtime of recovering N-degree polynomial secret (i.e. f(0)) at one normal ECU 
- Used in the SSKT protocol 
- ACSAC-2020 paper "Session Key Distribution Made Practical for CAN and CAN-FD Message Authentication"
- Please refer to Eq. 1 of the paper for the math behind the polynomial secret recovery and Section 6.1 for evaluation specs
- Author: Yang Xiao <xiaoy@vt.edu> */

#include <SPI.h>
#include <Crypto.h>
#include <string.h>
#include <GF256.h>
#include <RNG.h>


const int N_MAX = 10;
const int ECU = 0;
const unsigned long Repeat = 10000;



// Simulating the pre-shared x-coordinates of 10 auxiliary vectors
// Same aux x coordinate for every byte
uint8_t auxX[10] = {0xf9,0x46,0x3,0x1,0xcf,0x1e,0x48,0xb3,0x56,0x4d};

// x-coordinates of the ECU keys
unsigned char Pre_shared_key_x[10][16] = {
{0x63,0x4a,0xcc,0xa0,0xcc,0xd6,0xe,0xe0,0xad,0x70,0xd2,0xdb,0x9e,0xd2,0xa3,0x28},
{0x2c,0xeb,0x89,0x11,0x5e,0x74,0xe6,0xd8,0xf6,0x8d,0xe2,0x33,0xad,0xb7,0x7b,0x4f},
{0x4f,0x9d,0xae,0xca,0xe3,0x15,0xad,0xf8,0x2d,0x73,0x39,0x83,0x29,0x99,0xcb,0x3c},
{0xc1,0x3d,0x28,0xec,0x84,0xe6,0xb7,0x49,0x9e,0xd7,0xa9,0x7e,0xdd,0x4,0x8f,0xf6},
{0x5b,0x47,0x27,0xe8,0x3c,0xb,0xf1,0x36,0xee,0x93,0xb,0x35,0x76,0xed,0x6a,0x2},
{0x1b,0x28,0xde,0x9b,0xd6,0x9c,0xb4,0x6,0x77,0xf5,0x4f,0xb7,0xd4,0x15,0x78,0x76},
{0x38,0xbb,0x9d,0x8f,0x1c,0xb3,0x42,0x46,0x8c,0x9d,0x4c,0x5f,0x42,0xbe,0x9a,0xc},
{0xdc,0xcd,0x1c,0x5b,0x98,0x26,0xb8,0x2d,0x31,0x96,0x92,0xf7,0xb3,0xaf,0x2d,0x8f},
{0x6b,0x30,0xe9,0x4e,0x95,0x6,0x1,0xe7,0xbd,0xe9,0xae,0x88,0x91,0x88,0xb6,0xa3},
{0x57,0x01,0x42,0xbc,0x18,0xfb,0xbc,0xf0,0x62,0x1d,0x50,0x68,0x2a,0xc,0x4a,0x51}
};

// y-coordinates of the ECU key
unsigned char Pre_shared_key_y[10][16] = {
{0x33,0x69,0x92,0x70,0x1c,0x3a,0xad,0x5,0x75,0x5b,0x9b,0x64,0x3f,0x9b,0x72,0xbd},
{0xce,0xda,0x31,0x94,0x8e,0x39,0xdd,0x10,0x4a,0xe5,0xe4,0xfb,0xcd,0x2e,0x64,0x27},
{0x34,0xbb,0xf7,0x19,0x2b,0x85,0x28,0x90,0x53,0x7b,0x5f,0x6a,0x7e,0xbd,0xd6,0xfd},
{0x96,0xd7,0xd0,0x92,0x7,0x42,0xe4,0xca,0x28,0xb6,0xac,0x59,0x60,0xab,0xa9,0xa6},
{0xe,0x02,0x23,0xd2,0x1c,0x1f,0x14,0xff,0x73,0xf0,0x95,0xab,0x52,0xae,0x3,0x8b},
{0x31,0xcb,0x5c,0xe9,0x7,0xc4,0x4a,0xca,0x58,0xbd,0xfa,0xa0,0x77,0x4d,0x47,0xfd},
{0xa,0x27,0x43,0xd5,0xcc,0xf,0xff,0x9f,0x5b,0xce,0x23,0x34,0xcd,0x81,0xc3,0xb2},
{0x81,0x3d,0x81,0x79,0x19,0x5,0xd5,0x77,0xde,0x5b,0x99,0xd9,0xcc,0x54,0x16,0xff},
{0x7d,0x5d,0x61,0xca,0x93,0x89,0xeb,0xa4,0x2d,0xb8,0xd,0xbc,0x8b,0x83,0x41,0xa6},
{0x2c,0xff,0xb6,0x2c,0xdc,0xa9,0x35,0x3a,0x99,0xc3,0xab,0x2d,0xb5,0xa,0xd8,0x67}
};

unsigned long t0, t1, t2, t3;

void setup()
{
  Serial.begin(115200);

  Serial.print("N\t");
//  Serial.print("Precomp (mu)\t");
  Serial.print("Comp (mu)\t");
  Serial.print("Per byte (mu)\t\t");
  Serial.println("Key Recovered\t");
//  Serial.println();
  
  
  for(int N = 1;N <= N_MAX;N++)
  {
    uint8_t LaCo[N+1][16]; // Lagrange Coefficients, to pre-compute
    uint8_t skey[16]; // Secret key
    uint8_t skey_rec1[16], skey_rec2[16]; // Secret key to recover
    uint8_t R[N][16]; // Random challenges
    unsigned char auxY[N][16]; // y-coordinates to receive from Key Server in KD_MSG
    uint8_t points_x[N+1];
    uint8_t points_y[N+1];
  
    // Generate random secret key and R values
    RNG.begin("rand sec");
    RNG.rand(skey, 16);
    RNG.rand(&R[0][0], N*16);

    /*
    // Compute aux y-coordinates (at Key Server)
    for(int b=0;b<16;b++)
    { 
      for(int i=0;i<N;i++)
      {
        points_x[i] = Pre_shared_key_x[i][b];
        points_y[i] = Pre_shared_key_y[i][b]^R[i][b];
      }
      points_x[N] = 0;
      points_y[N] = skey[b];
      for(int n=0; n<N; n++)
      {
        // Largrange Interpolation
        auxY[n][b] = 0;
        for(int i=0;i<N+1;i++)
        {
          uint8_t tmp=0;
          for(int j=0;j<N+1;j++)
          {
            if(j!=i)
            {
              tmp = ((tmp+GF256_Log[auxX[i]^points_x[j]])%0xff+GF256_Log[GF256_Inv[points_x[j]^points_x[i]]])%0xff;
            }
          }
          auxY[n][b] ^= (points_y[i] != 0x0)? GF256_Exp[(GF256_Log[points_y[i]]+tmp)%0xff] : 0x0;
        }
        // ------------------------
      }
    }//*/

    t0 = micros();
    /*
    // Pre-compute Lagrange coefficients
    for(int b = 0;b < 16;b++)
    {
      for(int i = 0;i < N;i++)
      {
        LaCo[i][b] = 0;
        for(int j = 0;j < N;j++)
        {
          if(j != i)
          {
            LaCo[i][b] = ((LaCo[i][b]+GF256_Log[auxX[j]])%0xff + GF256_Log[GF256_Inv[auxX[j]^auxX[i]]])%0xff;
          }
        }
        LaCo[i][b] = ((LaCo[i][b]+GF256_Log[Pre_shared_key_x[ECU][b]])%0xff + GF256_Log[GF256_Inv[Pre_shared_key_x[ECU][b]^auxX[i]]])%0xff;
        LaCo[i][b] = GF256_Exp[LaCo[i][b]];
      }
  
      LaCo[N][b] = 0;
      for(int j = 0;j < N;j++)
      {
        LaCo[N][b] = ((LaCo[N][b]+GF256_Log[auxX[j]])%0xff + GF256_Log[GF256_Inv[auxX[j]^Pre_shared_key_x[ECU][b]]])%0xff;
      }
      LaCo[N][b] = GF256_Exp[LaCo[N][b]];
    }//*/

    t1 = micros();

    /*
    // Original Lagrange interpolation (at ECU)
    for(int r=0;r<Repeat;r++)
    {
      for(int b=0;b<16;b++)
      { 
        for(int i=0;i<N;i++)
        {
          points_x[i] = auxX[i];
          points_y[i] = auxY[i][b];
        }
        points_x[N] = Pre_shared_key_x[ECU][b];
        points_y[N] = Pre_shared_key_y[ECU][b]^R[ECU][b];
  
        // Largrange Interpolation
        skey_rec1[b] = 0;
        for(int i=0;i<N+1;i++)
        {
          uint8_t tmp=0;
          for(int j=0;j<N+1;j++)
          {
            if(j!=i)
            {
              tmp = ((tmp+GF256_Log[points_x[j]])%0xff+GF256_Log[GF256_Inv[points_x[j]^points_x[i]]])%0xff;
            }
          }
          skey_rec1[b] ^= (points_y[i] != 0x0)? GF256_Exp[(GF256_Log[points_y[i]]+tmp)%0xff] : 0x0;
        }
        // ------------------------
      }
    }
    //*/
    delay(200);
    t2 = micros();
    // Our method: recovering secret key using pre-computed Lagrange coeffs
    uint8_t tmp;
    for(int r=0;r<Repeat;r++)
    {
      for(int b=0;b<16;b++)
      {
        skey_rec2[b]=0;
        for(int i=0;i<N;i++)
        {
//          skey_rec2[b] ^= (auxY[i][b]!=0x0)? GF256_Exp[(GF256_Log[auxY[i][b]]+GF256_Log[LaCo[i][b]])%0xff] : 0x0;
          tmp = GF256_Log[auxY[i][b]]+GF256_Log[LaCo[i][b]];
          skey_rec2[b] ^= (auxY[i][b]!=0x0)? GF256_Exp[(tmp<=0xff)?tmp:(tmp-0xff)] : 0x0;
        }
//        skey_rec2[b] ^= (Pre_shared_key_y[ECU][b]!=R[ECU][b])? GF256_Exp[(GF256_Log[Pre_shared_key_y[ECU][b]^R[ECU][b]]+GF256_Log[LaCo[N][b]])%0xff] : 0x0;
        tmp = GF256_Log[Pre_shared_key_y[ECU][b]^R[ECU][b]]+GF256_Log[LaCo[N][b]];
        skey_rec2[b] ^= (Pre_shared_key_y[ECU][b]!=R[ECU][b])? GF256_Exp[(tmp<=0xff)?tmp:(tmp-0xff)] : 0x0;
      }
    }
    t3 = micros();
    
    Serial.print(N);
    Serial.print("\t");
//    Serial.print((t1-t0)/Repeat);
//    Serial.print("\t\t");
//    Serial.print((t2-t1)/Repeat);
//    Serial.print("\t\t");
    Serial.print((t3-t2));
    Serial.print("\t\t");
    Serial.print((t3-t2)/16);
    Serial.print("\t\t");
    
    for(int b=0;b<16;b++)
    {
      Serial.print(skey[b], HEX);
      Serial.print(" ");
    }
    Serial.print("\t\t");
    Serial.println();
    /*
    for(int b=0;b<16;b++)
    {
      Serial.print(skey_rec1[b], HEX);
      Serial.print(" ");
    }
    Serial.print("\t\t");
    Serial.println();
    for(int b=0;b<16;b++)
    {
      Serial.print(skey_rec2[b], HEX);
      Serial.print(" ");
    }
    Serial.println();
    //*/
  }
}

void loop()
{
}
