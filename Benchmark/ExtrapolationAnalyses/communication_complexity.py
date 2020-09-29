# For ACSAC'20 Paper: "Session Key Distribution Made Practical for CAN and CAN-FD Message Authentication"
# Plotting the extrapolated total communication overhead (Figure. 8)
#
# Yang Xiao <xiaoy@vt.edu>

import numpy as np
import matplotlib.pyplot as plt


N = [5,10]  # Number of normal ECUs
M = [5,10,15,20,25,30,35,40,45,50]  # Number of message IDs (we assume all ECUs subscribe to all message IDs)

# Protocol message counts, as in Table 2. We assume CAN-FD frame is transmitted at 5 times of the CAN bit rate
SKDC_KD    = 524
SKDC_CO    = 222
SKDC_KD_FD = 110
SKDC_CO_FD = 64
SSKT_RD    = 350
SSKT_CO    = 222
SSKT_RD_FD = 90
SSKT_CO_FD = 64

# Init Stats
SKDC_Total    = np.zeros((len(N),len(M)))
SKDC_Total_FD = np.zeros((len(N),len(M)))
SSKT_Total    = np.zeros((len(N),len(M)))
SSKT_Total_FD = np.zeros((len(N),len(M)))

for i in range(len(N)):
	n = N[i]
	for j in range(len(M)):
		m = M[j]
		SKDC_Total[i,j]    = SKDC_KD    * n * m  +  SKDC_CO    * n
		SKDC_Total_FD[i,j] = SKDC_KD_FD * n * m  +  SKDC_CO_FD * n
		SSKT_Total[i,j]    = SSKT_RD * n  +  262 * (1 + n) * m  +  SSKT_CO  * n


		SSKT_KD_FD = 0
		if n % 4 == 0:
			SSKT_KD_FD = 84  + 161 * n     / 4
		elif n % 4 == 1:
			SSKT_KD_FD = 109 + 161 * (n-1) / 4
		elif n % 4 == 2:
			SSKT_KD_FD = 136 + 161 * (n-2) / 4
		else:
			SSKT_KD_FD = 161 + 161 * (n-3) / 4

		SSKT_Total_FD[i,j] =  SSKT_RD * n  +  SSKT_KD_FD * m + SSKT_CO_FD * n


# Unit: ms, using CAN bit rate = 500kb/s
SKDC_Total    = SKDC_Total    / 500
SKDC_Total_FD = SKDC_Total_FD / 500
SSKT_Total    = SSKT_Total    / 500
SSKT_Total_FD = SSKT_Total_FD / 500

plt.plot(SKDC_Total[0],    color='red', linestyle='-')
plt.plot(SKDC_Total[1],    color='red', linestyle='--')
plt.plot(SKDC_Total_FD[0], color='red',   linestyle='-.')
plt.plot(SKDC_Total_FD[1], color='red',   linestyle='dotted')
plt.plot(SSKT_Total[0],    color='blue',  linestyle='-')
plt.plot(SSKT_Total[1],    color='blue',  linestyle='--')
plt.plot(SSKT_Total_FD[0], color='blue', linestyle='-.')
plt.plot(SSKT_Total_FD[1], color='blue', linestyle='dotted')

plt.legend([
	'SKDC CAN, $N=5$', 'SKDC CAN, $N=10$',
	'SKDC CAN-FD, $N=5$', 'SKDC CAN-FD, $N=10$',
	'SSKT CAN, $N=5$', 'SSKT CAN, $N=10$',
	'SSKT CAN-FD, $N=5$', 'SSKT CAN-FD, $N=10$'], fontsize='13')

print('SKDC_Total_FD[1]:', SKDC_Total_FD[1])
print('SSKT_Total_FD[1]:', SSKT_Total_FD[1])


plt.xlabel('$M$ (Number of Message IDs)', fontsize='15')
plt.ylabel('Communication Overhead (ms)', fontsize='15')
plt.ylim([0,540])
plt.xticks(range(len(M)),['5','10','15','20','25','30','35','40','45','50'], fontsize='13')
plt.yticks(fontsize='13')
plt.grid()
plt.show()