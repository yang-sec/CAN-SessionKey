# For ACSAC'20 Paper: "Session Key Distribution Made Practical for CAN and CAN-FD Message Authentication"
# Plotting the extrapolated total computation workload
#
# Yang Xiao <xiaoy@vt.edu>

import numpy as np
import matplotlib.pyplot as plt


N = [2,5,10]  # Number of normal ECUs
M = [5,10,15,20,25,30,35,40,45,50]  # Number of message IDs (we assume all ECUs subscribe to all message IDs)

# Runtime results (ms/byte) obtained from the three Arduino benchmark experiments (also shown in Table 2)
AES_SMALL_DE = 0.01233
AES_SMALL_EN = 0.00706
AES_SMALL_SETKEY = 0.02366 # One time
AES_TINY128_EN = 0.00723
AES_TINY128_SETKEY = 0.00125
BLAKE2s = 0.00080
BLAKE2s_FIN = 0.05314 # One time
BLAKE2s_SETKEY = 0.05509 # One time, keyed mode
F = [0,0,0] # Recovering polynomial secret of degree 2, 5, 10 per byte


SKDC_Total = np.zeros((len(N),len(M)))
SSKT_Total = np.zeros((len(N),len(M)))

for i in range(len(N)):
	n = N[i]
	for j in range(len(M)):
		m = M[j]

		SKDC_Total[i,j] += (AES_SMALL_SETKEY + AES_SMALL_DE*16) * m  # AES-decryption in m KD_MSGs
		SKDC_Total[i,j] += (BLAKE2s_SETKEY + BLAKE2s*(4+8+16) + BLAKE2s_FIN) * m  # MAC in m KD_MSGs
		SKDC_Total[i,j] += BLAKE2s_SETKEY + BLAKE2s*(4+8+16*m) + BLAKE2s_FIN  # MAC in 1 CO_MSG MAC (session keys digested)
		
		SSKT_Total[i,j] += BLAKE2s_SETKEY + BLAKE2s*(4+8+16) + BLAKE2s_FIN  # MAC in 1 PR_MSG MAC
		SSKT_Total[i,j] += (AES_TINY128_SETKEY + AES_TINY128_EN*16) * m  # Compute m Rs
		SSKT_Total[i,j] += (BLAKE2s_SETKEY + BLAKE2s*(4+8) + BLAKE2s_FIN) * m  # MAC in m KD_MSGs
		SSKT_Total[i,j] += BLAKE2s_SETKEY + BLAKE2s*(4+8+16*m) + BLAKE2s_FIN  # MAC in 1 CO_MSG MAC (session keys digested)
		SSKT_Total[i,j] += F[i]*16*m  # 16 bytes of f(0) recovery for m message IDs


plt.plot(SKDC_Total[0],    color='red', linestyle='-')
plt.plot(SSKT_Total[0],    color='blue',  linestyle='-')
plt.plot(SSKT_Total[1],    color='blue',  linestyle='--')
plt.plot(SSKT_Total[2],    color='blue',  linestyle='-.')

plt.legend([
	'SKDC',
	'SSKT, $N=2,5,10$'], fontsize='13')

plt.xlabel('$M$ (Number of Message IDs)', fontsize='15')
plt.ylabel('Computation Workload (ms)', fontsize='15')
plt.xticks(range(len(M)), ['5','10','15','20','25','30','35','40','45','50'], fontsize='13')
plt.yticks(fontsize='13')
plt.grid()
plt.show()