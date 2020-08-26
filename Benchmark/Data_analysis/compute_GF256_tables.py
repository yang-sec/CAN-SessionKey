#Compute GF(256) multiplicative and divisive tables
from pyfinite import ffield
import numpy as np

W = 8
F = ffield.FField(W)

def str_append(s, n):
    output = ''
    i = 0
    while i < n:
        output += s
        i = i + 1
    return output

GF_mul_table = np.zeros((2**W,2**W))
GF_div_table = np.zeros((2**W,2**W))
GF_exp_table = np.zeros(2**W) # generator: 0x03
GF_log_table = np.zeros(2**W) # generator: 0x03
GF_mul_table_str = ''
GF_div_table_str = ''
GF_exp_table_str = '' 
GF_log_table_str = '' 
gen = 0x03


for i in range(2**W):
	GF_mul_table_str = GF_mul_table_str + '{'
	GF_div_table_str = GF_div_table_str + '{'

	if i == 0:
		GF_exp_table[i] = 1
		GF_exp_table_str = GF_exp_table_str + '1,'
	else:
		GF_exp_table[i] = int(F.Multiply(int(GF_exp_table[i-1]),3))
		GF_exp_table_str = GF_exp_table_str + str(int(GF_exp_table[i]))
		
		if i < 2**W-1:
			GF_exp_table_str = GF_exp_table_str + ','

	# for j in range(2**W):
	# 	GF_mul_table_str = GF_mul_table_str + str(F.Multiply(i,j))
	# 	if i == 0:
	# 		GF_div_table_str = GF_div_table_str + '0'
	# 	else:
	# 		GF_div_table_str = GF_div_table_str + str(F.Divide(i,j))

	# 	if j < 2**W-1:
	# 		GF_mul_table_str = GF_mul_table_str + ','
	# 		GF_div_table_str = GF_div_table_str + ','

	# GF_mul_table_str = GF_mul_table_str + '}'
	# GF_div_table_str = GF_div_table_str + '}'
	# if i < 2**W-1:
	# 	GF_mul_table_str = GF_mul_table_str + ',\n'
	# 	GF_div_table_str = GF_div_table_str + ',\n'

print(GF_exp_table)
print(int(np.where(GF_exp_table)==2))

# Log table
for i in range(2**W):
	if i == 0:
		GF_log_table[i] = 0
		GF_log_table_str = GF_log_table_str + '0,'
	else:
		GF_log_table[i] = int(np.where(GF_exp_table)==i)
		GF_log_table_str = GF_log_table_str + str(GF_log_table[i])
		
		if i < 2**W-1:
			GF_log_table_str = GF_log_table_str + ','



GF256 = open(r'GF256_new.txt','w+')

# GF256.write('unsigned int GF256_Mul[256][256] = {\n' + GF_mul_table_str + '\n}\n\n')
# GF256.write('unsigned int GF256_Div[256][256] = {\n' + GF_div_table_str + '\n}')
GF256.write('unsigned int GF256_Exp[256] = {\n' + GF_exp_table_str + '\n}')
GF256.write('\n\nunsigned int GF256_Log[256] = {\n' + GF_log_table_str + '\n}')
# print(GF_mul_table_str)
# print(GF_div_table_str)
