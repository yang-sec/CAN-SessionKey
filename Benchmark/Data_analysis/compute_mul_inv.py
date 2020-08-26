import numpy as np
m = 251
invs = '0'

def str_append(s, n):
    output = ''
    i = 0
    while i < n:
        output += s
        i = i + 1
    return output

for i in range(m):
	if i==0:
		continue
	a = i % m
	for x in range(1,m):
		if (a*x)%m==1:
			invs = invs + ',' + str(x)

print(invs)
