from pwn import *
from Crypto.Util.number import *
from random import choice
from sage.all import * 
from elliptic_curve import Curve, Point
# E = EllipticCurve(Zmod(p), [a, b])
# G = E.gen(0)
# order = G.order()
# discrete_log(K, G, operation="+")計算 dG = K 的 d


p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
# print(a)

dlogs = []
primes = []

for i in range(20):
    print("Round:", i)
    r = remote("10.113.184.121",10034)

    # Ensure the elliptic curve is not singular.
    b = randint(1, p)
    while pow(4*a**3 + 27*b**2, 1, p) == 0:
        b = randint(1, p)


    E = EllipticCurve(Zmod(p), [a, b])
    order = E.order()
    factors = prime_factors(order)
    print("Get Factors!")

    # Avoid using too large prime, because it may cost lots of time.
    wanted_factors = []
    for factor in factors:
        if factor <= 2**40:
            wanted_factors.append(factor)
    prime = wanted_factors[-1]

    G = E.gen(0) * int(order / prime)
    Gx, Gy =  G.xy()
    
    
    r.sendlineafter(b"Gx: ", str(G[0]).encode())
    r.sendlineafter(b"Gy: ", str(G[1]).encode())
    
    ret = r.recvline().decode()
    print("Ret = ", ret)
    r.close()
    m = ret.lstrip("(").rstrip(")\n").split(",")
    K = E(m[0], m[1])
    print("K = ", K)

    log = discrete_log(K, G, operation="+")
    print("Dlog = ", log)
    print("Prime = ", prime)

    if log != None:
        dlogs.append(log)
        primes.append(prime)


ans = CRT_list(dlogs, primes)
flag = long_to_bytes(ans)
print("flag = ", flag)
