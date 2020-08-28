#include <Crypto.h>
#include <string.h>
#include <GF256.h>
#include <SSKT_TestData.h>

// GF256 Multiplication implemented with logarithm and exponentiation
unsigned char GF256Multiply(unsigned char a, unsigned char b)
{
    unsigned int logsum = GF256_Log[a] + GF256_Log[b];
    if(logsum > 0xff)
    {
        logsum -= 0xff;
    }
    return GF256_Exp[logsum];
}

void setup()
{
    Serial.begin(9600);
    double start, endt, elapsed;
    
    int R = 16; //16
    int Repeat = 100;
    int fzero[R];
    int N, repeat, r, i, j;

    // Temporary variables
    unsigned int tmp_quot_sum, tmp_prod_sum, tmp_prod_v_sum;
    unsigned char tmp_inv, tmp_quot, tmp_prod, tmp_prod_v;

    // Lagrange coefficients to pre-compute
    unsigned char Lagr_Prod_Full[R], Lagr_Prod[R][20];

    
    for(N = 1;N <= 10;N++) // N: number of auxilliary points (N-degree polynomial)
    {
        // Pre-compute
        for(r = 0;r < R;r++)
        {
            // Lagrange coefficient when the outer loop index corresponds to the ECU secret x
            Lagr_Prod_Full[r] = 1; 
            for(j = 0;j < N;j++)
            {
                tmp_inv = GF256_Inv[px[r][j]^sx[r]];
                tmp_quot = GF256Multiply(px[r][j], tmp_inv);
                Lagr_Prod_Full[r] = GF256Multiply(Lagr_Prod_Full[r], tmp_quot);                
            }

            // Lagrange coefficient when the outer loop index corresponds to an auxilliary point
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
                    tmp_quot = GF256Multiply(px[r][j],tmp_inv);
                    Lagr_Prod[r][i] = GF256Multiply(Lagr_Prod_Full[r], tmp_quot);
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

                // When the outer loop index corresponds to the ECU secret x
                tmp_prod_v = GF256Multiply(sy[r],Lagr_Prod_Full[r]);
                fzero[r] ^= tmp_prod_v;
                            
                // When the outer loop index corresponds to an auxilliary point
                for(i = 0;i < N;i++)
                {
                    tmp_prod_v = GF256Multiply(py[r][i], Lagr_Prod[r][i]);      
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

        Serial.print("\n16-byte secret recovered: ");
        for(r = 0;r < R;r++)
        {
            Serial.print(fzero[r]);
            Serial.print(" ");
        }

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
