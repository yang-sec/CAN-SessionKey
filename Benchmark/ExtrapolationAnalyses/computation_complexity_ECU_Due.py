# For ACSAC'20 Paper: "Session Key Distribution Made Practical for CAN and CAN-FD Message Authentication"
# Plotting the extrapolated total computation workload (Figure. 7)
#
# Yang Xiao <xiaoy@vt.edu>

import numpy as np
import matplotlib.pyplot as plt


N = [2,5,10]  # Number of normal ECUs
M = np.array([5,10,15,20,25,30,35,40,45,50])  # Number of message IDs (we assume all ECUs subscribe to all message IDs)

# Runtime results (ms/byte) obtained from the three Arduino benchmark experiments (also shown in Table 2)
AES_DE = 0.01123  # AES128 decryption per byte
AES_EN = 0.00584  # AES128 encryption per byte
AES_SETKEY = 0.03510
BLAKE2s = 0.00080 # BLAKE2s per byte
BLAKE2s_FIN = 0.05314 # BLAKE2s finalization
BLAKE2s_SETKEY = 0.05509 # BLAKE2s key setup in keyed mode
F = [0,0,0] # Recovering polynomial secret of degree 2, 6, 10 per byte


SKDC_Total = np.zeros((len(N),len(M)))
SSKT_Total = np.zeros((len(N),len(M)))

for i in range(len(N)):
	n = N[i]
	for j in range(len(M)):
		m = M[j]

		SKDC_Total[i,j] += (AES_DE*16 + AES_SETKEY) * m  # AES-decryption in m KD_MSGs
		SKDC_Total[i,j] += (BLAKE2s*(16+4+8+16) + BLAKE2s_SETKEY + BLAKE2s_FIN) * m  # MAC in m KD_MSGs
		SKDC_Total[i,j] += BLAKE2s*(16+4+8+16*m) + BLAKE2s_SETKEY + BLAKE2s_FIN  # MAC in 1 CO_MSG MAC (session keys digested)
		
		SSKT_Total[i,j] += BLAKE2s*(16+4+8+16) + BLAKE2s_SETKEY + BLAKE2s_FIN  # MAC in 1 PR_MSG MAC
		SSKT_Total[i,j] += (BLAKE2s*(16+16+4) + BLAKE2s_FIN) * m  # Compute m Rs
		SSKT_Total[i,j] += (BLAKE2s*(16+4+8) + BLAKE2s_SETKEY + BLAKE2s_FIN) * m  # MAC in m KD_MSGs
		SSKT_Total[i,j] += BLAKE2s*(16+4+8+16*m) + BLAKE2s_SETKEY + BLAKE2s_FIN  # MAC in 1 CO_MSG MAC (session keys digested)
		SSKT_Total[i,j] += F[i]*16*m  # 16*m bytes of f(0) recovery


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