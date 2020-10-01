# For ACSAC'20 Paper: "Session Key Distribution Made Practical for CAN and CAN-FD Message Authentication"
# Plotting the hardware experiment results - running an entire session
#
# Yang Xiao <xiaoy@vt.edu>

import numpy as np
import matplotlib.pyplot as plt


N = [2,3,4,5,6]  # Number of normal ECUs
M = [1,6]  # Number of message IDs (we assume all ECUs subscribe to all message IDs)


T_KeyGen_SKDC_M1 = np.array([4.67,	4.68,	4.69,	4.69,	4.69])
T_KeyDis_SKDC_M1 = np.array([
[19.76,	21.41,	23.16,	24.88,	26.64],
[19.79,	21.43,	23.15,	24.98,	26.6],
[19.76,	21.47,	23.15,	24.88,	26.67],
[19.75,	21.46,	23.2,	24.87,	26.62]])

# KdDELAY = 6.8ms
T_KeyGen_SKDC_M6 = np.array([4.7,	4.7,	4.66,	4.65,	4.73])
T_KeyDis_SKDC_M6 = np.array([ 
[74.29,	84.34,	96.41,	107.14,	115.53],
[74.17,	84.35,	96.08,	107.46,	115.55],
[74.31,	84.28,	96.36,	107.29,	115.48],
[74.34,	84.45,	96.18,	107.1,	115.55]])

# PrDELAY = 5.7ms
T_KeyGen_SSKT_M1 = np.array([4.75,	4.69,	4.76,	4.72,	4.77])
T_KeyDis_SSKT_M1 = np.array([
[28.25,	32,	36.14,	39.41,	43.77],
[28.18,	32.01,	36.17,	39.43,	43.71],
[28.14,	31.95,	35.9,	39.4,	43.79],
[28.21,	31.98,	35.91,	39.5,	43.76]])

# PrDELAY = 5.7ms, KdDELAY = [6.5, 6.2, 5.5, 4.4]ms
T_KeyGen_SSKT_M6 = np.array([4.78,	4.74,	4.79,	4.75])
T_KeyDis_SSKT_M6 = np.array([
[78.32,	87.29,	94.62,	102.14],
[78.41,	86.49,	94.57,	101.69],
[78.35,	86.96,	94.62,	102.11],
[78.47,	87.02,	94.6,	101.79]])

TT_SKDC_M1_AVG = np.mean(T_KeyGen_SKDC_M1 + T_KeyDis_SKDC_M1, axis=0)
TT_SKDC_M1_STD = np.std(T_KeyGen_SKDC_M1 + T_KeyDis_SKDC_M1, axis=0)
TT_SKDC_M6_AVG = np.mean(T_KeyGen_SKDC_M6 + T_KeyDis_SKDC_M6, axis=0)
TT_SKDC_M6_STD = np.std(T_KeyGen_SKDC_M6 + T_KeyDis_SKDC_M6, axis=0)
TT_SSKT_M1_AVG = np.mean(T_KeyGen_SSKT_M1 + T_KeyDis_SSKT_M1, axis=0)
TT_SSKT_M1_STD = np.std(T_KeyGen_SSKT_M1 + T_KeyDis_SSKT_M1, axis=0)
TT_SSKT_M6_AVG = np.mean(T_KeyGen_SSKT_M6 + T_KeyDis_SSKT_M6, axis=0)
TT_SSKT_M6_STD = np.std(T_KeyGen_SSKT_M6 + T_KeyDis_SSKT_M6, axis=0)


# plt.errorbar(N, TT_SKDC_M1_AVG, yerr=TT_SKDC_M1_STD, color='black',  fmt='-D', capsize=4, markersize=4)
# plt.errorbar(N, TT_SKDC_M6_AVG, yerr=TT_SKDC_M6_STD, color='red',  fmt='-<', capsize=4, markersize=4)
# plt.errorbar(N, TT_SSKT_M1_AVG, yerr=TT_SSKT_M1_STD, color='green',  fmt='->', capsize=4, markersize=4)
# plt.errorbar([2,3,4,5], TT_SSKT_M6_AVG, yerr=TT_SSKT_M6_STD, color='blue',  fmt='-s', capsize=4, markersize=4)

plt.plot(TT_SKDC_M1_AVG, 'o-',   color='red')
plt.plot(TT_SKDC_M6_AVG, 'o--',   color='red')
plt.plot(TT_SSKT_M1_AVG, 's-',  color='blue')
plt.plot(TT_SSKT_M6_AVG, 's--',  color='blue')

plt.legend([
	'SKDC, $M=1$',
	'SKDC, $M=6$',
	'SSKT, $M=1$',
	'SSKT, $M=6$'], fontsize='13')


plt.xlabel('$N$ (Number of ECUs)', fontsize='15')
plt.ylabel('Protocol Runtime (ms)', fontsize='15')
plt.ylim([0,130])
plt.xticks(range(len(N)),['2','3','4','5','6'], fontsize='13')
plt.yticks(fontsize='13')
plt.grid()
plt.show()