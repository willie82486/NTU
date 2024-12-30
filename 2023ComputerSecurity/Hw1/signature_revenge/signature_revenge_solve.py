from hashlib import sha256, md5
from ecdsa import SECP256k1
from Crypto.Util.number import bytes_to_long, long_to_bytes
from sage.all import *
import copy

n = int(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
# E = SECP256k1
# G, order = E.generator, E.order
# 115792089237316195423570985008687907852837564279074904382605163141518161494337
print(order)
K = 2**128 - 2**90
r1 = 26150478759659181410183574739595997895638116875172347795980556499925372918857
r2 = 8256687378196792904669428303872036025324883507048772044875872623403155644190
s1 = 50639168022751577246163934860133616960953696675993100806612269138066992704236
s2 = 90323515158120328162524865800363952831516312527470472160064097576156608261906
h1 = bytes_to_long(sha256(b"https://www.youtube.com/watch?v=IBnrn2pnPG8").digest())
h2 = bytes_to_long(sha256(b"https://www.youtube.com/watch?v=1H2cyhWYXrE").digest())

t = (1 - pow(s1, -1 ,n) * s2 * r1 * pow(r2, -1 ,n) * 2**128) * pow( (2**128 - pow(s1, -1, n) * s2 * r1 * pow(r2, -1, n)), -1 , n)
u = (pow(s1, -1, n) * r1 * h2 * pow(r2, -1, n) - pow(s1, -1, n) * h1) * pow( (2**128 - pow(s1, -1, n) * s2 * r1 * pow(r2, -1, n)), -1 , n)


mat = Matrix(QQ, [[n, 0, 0], [t, 1, 0], [u, 0, K]])

print("Det(mat) = ", det(mat))
print("K = ", K)
print("Det(L)^1/3 - K = ", pow(det(mat), 1/3)- K)

L = mat.LLL()
print("LLL:", L)


# print(L[0][1])
for row in L.rows():
    a = -row[0]
    b = row[1]
    k1 = a * 2**128 + b
    k2 = b * 2**128 + a
    if row[-1] == K:
        d1 = ((s1 * k1 - h1) * pow(r1, -1, n)) % n
        print(long_to_bytes(d1))
        d2 = ((s2 * k2 - h2) * pow(r2, -1, n)) % n
        print(long_to_bytes(d2))

copy_LLL = copy.deepcopy(L)
copy_LLL[0] = copy_LLL[0] + copy_LLL[1]
copy_LLL[2] = copy_LLL[0] + copy_LLL[2]
for row in copy_LLL.rows():
    a = -row[0]
    b = row[1]
    k1 = a * 2**128 + b
    k2 = b * 2**128 + a
    if row[-1] == K:
        d1 = ((s1 * k1 - h1) * pow(r1, -1, n)) % n
        print(long_to_bytes(d1))
        d2 = ((s2 * k2 - h2) * pow(r2, -1, n)) % n
        print(long_to_bytes(d2))