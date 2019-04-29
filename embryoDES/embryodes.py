sbox1=[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
	[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
	[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
	[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

def xor_bits(l,r):
	bits=''
	for i in range(0,len(l)):
		bits=bits+str((int(l[i],2)^int(r[i],2)))
	return bits
	
def F(plaintext, subkey):
	bits = [plaintext[x-1] for x in E]
	bits = xor_bits(bits, subkey)
	res = []
	for i in range(0, len(bits), 6):
		row = int(bits[i])*2+int(bits[i+5])
		col = int(bits[i+1])*8+int(bits[i+2])*4+int(bits[i+3])*2+int(bits[i+4])
		val = bin(sbox1[row][col])[2:]
		res.extend(map(int, list(val.rjust(4,'0'))))
	ciphertext=''
	for i in range(0,32):
		ciphertext=ciphertext+str(res[i])
	return ciphertext
def E_change(plaintext,a):
	bits=[plaintext[x-1] for x in E]
	num=''
	for i in range(0,6):
		num=num+bits[6*a+i]
	return int(num,2)

subkey=bin(0x12345678910)[2:]
#subkey是未知的，请根据题目给出的五个密文，求出subkey
chain=[0x92d91525,0x81c82636,0xa3d71597,0xc2a41239,0xa4824698,0x45681249]
for i in range(6):
	plaintext=bin(chain[i])[2:].zfill(32)
	print(hex(int(F(plaintext,subkey),2)))
	
