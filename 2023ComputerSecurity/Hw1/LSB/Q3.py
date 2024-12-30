#! /usr/bin/python3
from Crypto.Util.number import bytes_to_long, getPrime
import os

from secret import FLAG

p = getPrime(1024)
q = getPrime(1024)
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)

m = bytes_to_long(FLAG + os.urandom(256 - len(FLAG)))
assert m < n
enc = pow(m, e, n)
print(n)
print(e)
print(enc)
while True:
    inp = int(input().strip())
    pt = pow(inp, d, n)
    print(pt % 3)




e = 13
m1 = 48763
a = randrange(n)
b = randrange(n)
m2 = (m1*a + b) % n

c1 = pow(m1, e, n)
c2 = pow(m2, e, n)

F.<x> = PolynomialRing(Zmod(n))
g1 = x^e - c1
g2 = (a*x + b)^e -c2

print(g1(m1), g2(m1))
while g2 != 0:
    g1-= g1 // g2*g2
    g1, g2 = g2, g1

print(g1)
g1 = g1.monic()
print(g1)
print(-g1[0] % n)


# wienter's attack  
p = getPrime(256)
q = getPrime(256)
n = p * q
phi = (p-1) * (q-1)

d = randrange(math.isqrt(math.isqrt(n))//3)
e = inverse(d, phi)

f= continued_fraction(e/n)
ct = pow(48763, e, n)
for i in range (len(f)):
    k ,d = f.numerator(i), f.denominator(i)
    if pow(2, d*e, n) == 2:
        print(k, d)
        print(pow(ct, d, n))