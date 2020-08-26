#include <Crypto.h>
#include <AES.h>
#include <string.h>
//#include <MyCryto.h>
#include <GF256.h>
#include <SSKT_TestData.h>
#include <Z251.h>

void setup()
{
    Serial.begin(115200);
    double start, endt, elapsed;
    
    int R = 16; //16
    int Repeat = 100;
    int fzero[R];
    int N, repeat, r, i, j;

    unsigned int tmp_quot_sum, tmp_prod_sum, tmp_prod_v_sum;
    unsigned char tmp_inv, tmp_quot, tmp_prod, tmp_prod_v;

    // To pre-compute
    unsigned char Lagr_Prod_Full[R], Lagr_Prod[R][20];

    
    for(N = 1;N <= 10;N++) // N: number of auxilliary points (N-degree polynomial)
    {
        // Pre-compute
        for(r = 0;r < R;r++)
        {
            // Lagrange coefficient when the outer loop index is the ECU secret x
            Lagr_Prod_Full[r] = 1; 
            for(j = 0;j < N;j++)
            {
                tmp_inv = GF256_Inv[px[r][j]^sx[r]];

                // Multiply
                tmp_quot_sum = GF256_Log[px[r][j]] + GF256_Log[tmp_inv];
                if(tmp_quot_sum > 0xff) {tmp_quot_sum -= 0xff;}
                tmp_quot = GF256_Exp[tmp_quot_sum];

                // Multiply
                tmp_prod_sum = GF256_Log[Lagr_Prod_Full[r]] + GF256_Log[tmp_quot];
                if(tmp_prod_sum > 0xff) {tmp_prod_sum -= 0xff;}
                Lagr_Prod_Full[r] = GF256_Exp[tmp_prod_sum];                
            }

            // Lagrange coefficient when the outer loop index is an auxilliary point
            for(i = 0;i < N;i++)
            {
                Lagr_Prod[r][i] = 1;
                for(j = 0;j < N;j++)
                {
                    if(j == i) // To compute with the secret x instead
                    {
                        tmp_inv = GF256_Inv[px[r][j]^sx[r]];
                    }
                    else
                    {
                        tmp_inv = GF256_Inv[px[r][j]^px[r][i]];
                    }

                    // Multiply
                    tmp_quot_sum = GF256_Log[px[r][j]] + GF256_Log[tmp_inv];
                    if(tmp_quot_sum > 0xff) {tmp_quot_sum -= 0xff;}
                    tmp_quot = GF256_Exp[tmp_quot_sum];
    
                    // Multiply
                    tmp_prod_sum = GF256_Log[Lagr_Prod_Full[r]] + GF256_Log[tmp_quot];
                    if(tmp_prod_sum > 0xff) {tmp_prod_sum -= 0xff;}
                    Lagr_Prod[r][i] = GF256_Exp[tmp_prod_sum];
                }
            }
            
        }

                    
        // Main run
        start = micros();   
        for(repeat = 0;repeat < Repeat;repeat++)
        {
            for(r = 0;r < R;r++)
            {   
                fzero[r] = 0;

                // 1. If the outer loop is the ECU secret x
                // Multiply
                tmp_prod_v_sum = GF256_Log[sy[r]] + GF256_Log[Lagr_Prod_Full[r]];
                if(tmp_prod_v_sum > 0xff) {tmp_prod_v_sum -= 0xff;}
                tmp_prod_v = GF256_Exp[tmp_prod_v_sum];
                
                fzero[r] ^= tmp_prod_v;
                            
                // 2. If the outer loop is an auxilliary point
                for(i = 0;i < N;i++)
                {
                    // Multiply
                    tmp_prod_v_sum = GF256_Log[py[r][i]] + GF256_Log[Lagr_Prod[r][i]];
                    if(tmp_prod_v_sum > 0xff) {tmp_prod_v_sum -= 0xff;}
                    tmp_prod_v = GF256_Exp[tmp_prod_v_sum];
                    
                    fzero[r] ^= tmp_prod_v;
                }
            }
        }
        
        endt = micros();
//        Serial.print(micros());
//        
//        Serial.print(". start: ");
//        Serial.print(start);
//        Serial.print(". end: ");
//        Serial.print(endt);

//        Serial.print("16-byte secret recovered: ");
//        for(r = 0;r < R;r++)
//        {
//            Serial.print(fzero[r]);
//            Serial.print(" ");
//        }

        elapsed = endt - start;
        Serial.print("N(=deg+1)=");
        Serial.print(N);
        Serial.print(". Total Time: ");
        Serial.print(elapsed);
        Serial.print(" us. Per 128-bit key: ");
        Serial.print(elapsed/Repeat);
        Serial.print(" us. Per byte:  ");
        Serial.print(elapsed/Repeat/R);
        Serial.print(" us.\n");
    }
}

void loop()
{
}
