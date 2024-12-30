from Crypto.Util.number import *
from hashlib import sha256, md5
from ecdsa import SECP256k1
from ecdsa.ecdsa import Public_key, Private_key
import os
from math import log2


k1_list=[]
k2_list=[]
k1_k2_list=[]

flag_len = 16
d = os.urandom(32 - (32-flag_len)) + bytes([0x10] * flag_len)
d = bytes_to_long(d)
# print(d)
for i in range(1):
    
    magic1 = md5(d.to_bytes(32, "big")).digest()
    magic2 = md5(d.to_bytes(32, "big")[::-1]).digest()
    

    k1 = bytes_to_long(magic1 + magic2)
    k2 = bytes_to_long(magic2 + magic1)
    print("d = ", long_to_bytes(d))
    print("magic1 = ", magic1)
    print("magic2 = ", magic2)
    print("k1 = ", long_to_bytes(k1))
    print("k2 = ", long_to_bytes(k2))
    print("d_long = ", d)
    print("magic1_long = ", bytes_to_long(magic1))
    print("magic2_long = ", bytes_to_long(magic2))    
    print("k1_long = ", k1)
    print("k2_long = ", k2)

    a = k1/k2
    if a < 0:
        a = -a
    k1_k2_list.append(a)
    k1_list.append(log2(k1))
    k2_list.append(log2(k2))
    # print(bytes_to_long(magic1), k1)
    
print("k1_list, k2_list = ", (k1_list), (k2_list))
print("K1/K2 = ", k1_k2_list)

