from pwn import *
from Crypto.Util.number import long_to_bytes


r = remote("edu-ctf.zoolab.org",10005)
n = int(r.recvline().decode())
e = int(r.recvline().decode())
enc = int(r.recvline().decode())

mod = 3
mod_inv = pow(mod,-1,n)
mod_inv_e = pow(mod,-e,n)
ans = 0
counter = 1
remainder = 0
while counter <= n:
    r.sendline(str(enc).encode())
    ret = int(r.recvline().decode())
    # print("Ret = ", ret)
    x = (ret - remainder) % mod
    ans += x*counter
    
    enc = (enc*mod_inv_e) % n
    remainder = (remainder + x)*mod_inv % n
    counter *= mod 
    
print(ans)
print(long_to_bytes(ans))    
    