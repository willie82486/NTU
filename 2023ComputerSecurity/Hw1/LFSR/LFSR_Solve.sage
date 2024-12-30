import copy
from Crypto.Util.number import long_to_bytes
stream = [0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0]
unimpact_stream = [ 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1,
                    0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1,
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
                    1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0]
unimpact_stream = vector(unimpact_stream)

F.<x> = PolynomialRing(GF(2))

poly = x^64 + x^53 + x^41 + x^37 + x^23 + x^19 + x^17 + x^2 + x^0
matrix = companion_matrix(poly, format='bottom')

gathering_matrix = copy.deepcopy(matrix)
for i in range(256, 320, 1):
    tmp_accumulateMatrix = matrix ^ (70 + 71*(i))
    gathering_matrix[i-256] = tmp_accumulateMatrix[0]

# init_seed = gathering_matrix * unimpact_stream
init_seed = gathering_matrix.inverse() * unimpact_stream
# init_seed = unimpact_stream * gathering_matrix.inverse()
print("init_seed = ", init_seed)

encryption_txt = []
for i in range(256):
    tmp_seed = matrix ^ (70 + 71* (i))* init_seed 
    # tmp_seed = init_seed * matrix ^ (70 + 71*i)
    encryption_txt.append(tmp_seed[0])
# print(encryption_txt)

flag = []
for i in range(256):
    flag.append(int(encryption_txt[i]) ^^ (stream[i])) 
print("flag bits = ", flag)
print(long_to_bytes(int("".join(map(str,flag)),2)))