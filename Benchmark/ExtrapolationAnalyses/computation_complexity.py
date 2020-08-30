# For ACSAC'20 Paper: "Session Key Distribution Made Practical for CAN and CAN-FD Message Authentication"
# Plotting the extrapolated total computation workload (Figure. 7)
#
# Yang Xiao <xiaoy@vt.edu>

import numpy as np
import matplotlib.pyplot as plt


N = [2,6,10]  # Number of normal ECUs
M = [5,10,15,20,25,30,35,40,45,50]  # Number of message IDs (we assume all ECUs subscribe to all message IDs)

# Runtime results (ms/byte) obtained from the three Arduino benchmark experiments (also shown in Table 2)
AES = 0.0675  # AES128 decryption
HASH = 0.0611 # SHA3 and SHA3-HMAC
F = [0.0094,0.0206,0.0318] # Recovering polynomial secret of degree 2, 6, 10.


SKDC_Total    = np.zeros((len(N),len(M)))
SSKT_Total    = np.zeros((len(N),len(M)))

for i in range(len(N)):
	n = N[i]
	for j in range(len(M)):
		m = M[j]

		# 128 bits in KD_MSG AES-decryption
		# (128+11+18+64+128) bits in KD_MSG MAC
		# (128+11+64+256) bits in CO_MSG MAC
		# 128*m bits in digest computation
		SKDC_Total[i,j] = (AES*16 + HASH*44)*m + HASH*58 + HASH*16*m

		# 128 bits in RD_MSG AES-decryption
		# (128+11+64+128) bits in RD_MSG MAC
		# (2+18+64+128) bits in KD_MSG MAC
		# (128+11+64+256) bits in CO_MSG MAC
		# 128*m bits in digest computation
		# 16*m bytes in f(0) computation
		SSKT_Total[i,j] = AES*16 + HASH*42 + HASH*(2+18+64+128)/8 * m + HASH*58 + HASH*16*m + F[i]*16*m


plt.plot(SKDC_Total[0],    color='red', linestyle='-')
plt.plot(SSKT_Total[0],    color='blue',  linestyle='-')
plt.plot(SSKT_Total[1],    color='blue',  linestyle='--')
plt.plot(SSKT_Total[2],    color='blue',  linestyle='-.')

plt.legend([
	'SKDC',
	'SSKT, $N=2$', 'SSKT, $N=6$', 'SSKT, $N=10$'], fontsize='12')

plt.xlabel('$M$ (Number of Message IDs)', fontsize='14')
plt.ylabel('Computation Workload (ms)', fontsize='14')
plt.xticks(range(len(M)),['5','10','15','20','25','30','35','40','45','50'], fontsize='12')
plt.grid()
plt.show()