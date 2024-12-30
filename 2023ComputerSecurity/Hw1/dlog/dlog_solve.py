from pwn import *
from Crypto.Util.number import long_to_bytes, isPrime, getPrime
from random import choice
from sage.all import * 

N = 2
while True:
    bitLen = N.bit_length()
    if bitLen > 1024:
        N = 2
    if bitLen == 1024:
        if isPrime(N+1):
            print(N+1)
            break
    N *= getPrime(10)
N = 121727181761011866377464305332548889431279280834058773263063423327208847199105074978608539011117276269299218426134247361638684707111286927388280769350060449099836604708555179458349780631830405299403526489558253318274219698171385905669712961496670010752981562200919434118028503228057361873289524431244952596459
g = 7
r = remote("10.113.184.121",10032)
r.sendlineafter(b"give me a prime: ", str(N).encode())
r.sendlineafter(b"give me a number: ", str(g).encode())
ret = r.recvline().decode()
m = int(ret.lstrip("The hint about my secret:"))

FLAG = discrete_log( Mod(m, N), Mod(g, N))
# print("m,g,FLAG = ", m, g, FLAG)
# print(g)
print(long_to_bytes(FLAG))
