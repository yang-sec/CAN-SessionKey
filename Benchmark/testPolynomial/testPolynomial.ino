// Benchmarking the runtime of recovering N-degree polynomial secret (i.e. f(0)) at one normal ECU 
// Used in the SSKT protocol 
// ACSAC-2020 paper "Session Key Distribution Made Practical for CAN and CAN-FD Message Authentication"
// **Please refer to Eq. 1 of the paper for the math behind the polynomial secret recovery
//
// Yang Xiao <xiaoy@vt.edu>

#include <Crypto.h>
#include <string.h>
#include <GF256.h>

// Simulating the pre-shared x-coordinates of 10 auxiliary vectors
unsigned char px[16][10] = {
{215,78,84,246,19,205,119,142,112,244},
{1,164,117,32,126,181,22,130,163,167},
{42,12,110,233,1,160,80,4,78,166},
{4,28,44,196,50,228,123,186,198,159},
{221,73,242,45,167,187,113,72,30,190},
{176,63,126,61,165,200,196,40,129,172},
{32,65,19,244,182,17,198,239,63,192},
{231,1,67,116,69,48,219,141,167,247},
{218,121,62,206,127,104,115,93,151,226},
{207,118,73,30,158,102,13,29,220,20},
{31,160,41,156,157,93,155,243,151,241},
{91,11,157,2,107,239,103,1,112,226},
{83,93,227,22,43,224,174,16,33,211},
{233,226,246,221,220,209,44,131,212,223},
{209,111,245,50,37,33,6,233,12,41},
{154,92,225,137,87,70,132,64,149,228}
};

// Simulating the y-coordinates to received from KS in KD_MSG corresponding to the 10 auxiliary vectors
unsigned char py[16][10] = {
{96,23,34,103,98,70,201,41,91,41},
{205,43,120,111,238,2,218,154,90,228},
{87,235,43,139,97,235,95,250,198,94},
{166,242,38,9,144,27,224,62,90,118},
{216,183,60,38,10,67,138,209,220,59},
{133,79,154,221,205,231,143,27,153,72},
{109,255,191,179,204,179,66,96,210,219},
{152,91,208,186,112,149,196,206,65,36},
{5,142,155,246,221,151,244,85,50,102},
{56,161,239,252,59,11,32,4,203,136},
{216,92,10,38,39,203,179,19,85,222},
{15,13,190,152,21,28,148,78,31,33},
{198,34,190,65,52,220,139,117,134,32},
{171,96,14,23,188,253,91,86,144,19},
{122,33,234,98,219,25,135,14,230,181},
{91,121,69,229,97,143,115,173,221,128}
};

// x-coordinates of the ECU key
unsigned char sx[16] = {65,186,48,60,150,19,246,94,82,68,114,49,187,155,68,186};

// y-coordinates of the ECU key
unsigned char sy[16] = {30,132,46,124,168,163,128,96,205,219,52,171,145,58,243,215};

int K_LEN = 16; // Length of a  secret key, in bytes (16 by default)
int N_MAX = 10; // Max number of ECUs
int Repeat = 100;
    
void setup()
{
    Serial.begin(9600);
    // Temporary variables
    double start, endt, elapsed;
    unsigned int tmp_quot_sum, tmp_prod_sum, tmp_prod_v_sum;
    unsigned char tmp_inv, tmp_quot, tmp_prod, tmp_prod_v;    

    unsigned char Lagr_Prod_Full[K_LEN] = {1}; // Lagrange coefficients when the outer loop index corresponds to the ECU secret
    unsigned char Lagr_Prod[K_LEN][N_MAX] = {{1}}; // Lagrange coefficients when the outer loop index corresponds to an auxilliary point

    // Pre-compute Lagrange coefficients
    start = micros();
    for(int N = 1;N <= N_MAX;N++) // N = Number of auxilliary points = polynomial degree = number of ECUs
    {
        for(int b = 0;b < K_LEN;b++)
        {   
            // Compute Lagrange coefficients when the outer loop index corresponds to the ECU secret
            for(int j = 0;j < N;j++)
            {
                tmp_inv = GF256_Inv[px[b][j]^sx[b]];

                // Multiply (We write out the log-exp-based multiply implementation explicitly for minimal overhead)
                tmp_quot_sum = GF256_Log[px[b][j]] + GF256_Log[tmp_inv];
                if(tmp_quot_sum > 0xff) {tmp_quot_sum -= 0xff;}
                tmp_quot = GF256_Exp[tmp_quot_sum]; // The multiplcation result in GF256

                // Multiply
                tmp_prod_sum = GF256_Log[Lagr_Prod_Full[b]] + GF256_Log[tmp_quot];
                if(tmp_prod_sum > 0xff) {tmp_prod_sum -= 0xff;}
                Lagr_Prod_Full[b] = GF256_Exp[tmp_prod_sum];                
            }

            // Compute Lagrange coefficients when the outer loop index corresponds to an auxilliary point
            for(int i = 0;i < N;i++)
            {
                for(int j = 0;j < N;j++)
                {
                    if(j == i) // To compute with the secret x instead
                    {
                        tmp_inv = GF256_Inv[px[b][j]^sx[b]];
                    }
                    else
                    {
                        tmp_inv = GF256_Inv[px[b][j]^px[b][i]];
                    }

                    // Multiply
                    tmp_quot_sum = GF256_Log[px[b][j]] + GF256_Log[tmp_inv];
                    if(tmp_quot_sum > 0xff) {tmp_quot_sum -= 0xff;}
                    tmp_quot = GF256_Exp[tmp_quot_sum];
    
                    // Multiply
                    tmp_prod_sum = GF256_Log[Lagr_Prod[b][i]] + GF256_Log[tmp_quot];
                    if(tmp_prod_sum > 0xff) {tmp_prod_sum -= 0xff;}
                    Lagr_Prod[b][i] = GF256_Exp[tmp_prod_sum];
                }
            }  
        }
    }
    endt = micros();
    Serial.print("Runtime of pre-computing Lagrange coefficients (only needed once): ");
    Serial.print((endt-start)/1000);
    Serial.print(" ms.\n\n");

    
    // Main Run
    Serial.print("Runtime of recovering secret key: \n");
    int fzero[K_LEN]; // The f(0) to recover for all bytes
    for(int N = 1;N <= N_MAX;N++)
    {   
        delay(100);     
        start = micros();   
        for(int r = 0;r < Repeat;r++) // Repeat the computation $repeat times. Will calculate the average.
        {
            // Recover f(0) for each byte
            for(int b = 0;b < K_LEN;b++)
            {   
                fzero[b] = 0;

                // When the outer loop index corresponds to the ECU secret
                // Multiply
                tmp_prod_v_sum = GF256_Log[sy[b]] + GF256_Log[Lagr_Prod_Full[b]];
                if(tmp_prod_v_sum > 0xff) {tmp_prod_v_sum -= 0xff;}
                tmp_prod_v = GF256_Exp[tmp_prod_v_sum];
                
                fzero[b] ^= tmp_prod_v;
                            
                // When the outer loop index corresponds to an auxilliary point
                for(int i = 0;i < N;i++)
                {
                    // Multiply
                    tmp_prod_v_sum = GF256_Log[py[b][i]] + GF256_Log[Lagr_Prod[b][i]];
                    if(tmp_prod_v_sum > 0xff) {tmp_prod_v_sum -= 0xff;}
                    tmp_prod_v = GF256_Exp[tmp_prod_v_sum];
                    
                    fzero[b] ^= tmp_prod_v;
                }
            }
        }
        
        endt = micros();
        Serial.print("N=");
        Serial.print(N);
        Serial.print(". \t128-bit secret key recovered: 0x");
        for(int b = 0;b < K_LEN;b++)
        {
            Serial.print(fzero[b],HEX);
        }

        elapsed = endt - start;
        Serial.print(". \tRuntime: ");
        Serial.print(elapsed/Repeat);
        Serial.print(" us. \tRuntime per byte:  ");
        Serial.print(elapsed/Repeat/K_LEN);
        Serial.print(" us.\n");
    }
}

void loop()
{
}
