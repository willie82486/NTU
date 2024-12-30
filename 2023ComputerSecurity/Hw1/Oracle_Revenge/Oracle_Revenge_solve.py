from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.number import *
from random import randbytes
import os

def pad(m):
    length = 16-len(m) % 16
    return m + chr(length).encode()*length

def asymmetric_encryption(message, N, e):
    padded_message = message
    return pow(bytes_to_long(padded_message), e, N)

def sendmsg(r, key, iv, ct):
    r.sendlineafter(b'key: ', str(key).encode())
    r.sendlineafter(b'iv: ', str(iv).encode())
    r.sendlineafter(b'ciphertext: ', ct.hex().encode())

def padding_oracle_attack(r, aes_ECB, encrpto_key, encrpto_iv):
    Dct = bytearray(b"\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30")
   
    block_len = 16
    padding_num = 0
    for i in range(block_len-1,-1,-1):
        # print("I = ", i)
        padding_num += 1
        for j in range(i+1, block_len):
            Dct[j] ^= bytearray(chr(padding_num).encode())[0]
        for c in range(0, 256):
            print(c, end='\r')
            Dct[i] ^= c
            ct = aes_ECB.encrypt(Dct)
                
            r.sendlineafter(b'key: ', str(encrpto_key).encode())
            r.sendlineafter(b'iv: ', str(encrpto_iv).encode())
            r.sendlineafter(b'ciphertext: ', ct.hex().encode())
            # sendmsg(r, encrpto_key, encrpto_iv, ct)
            ret = r.recvline()
            # print(ret)

            if ret == b"OK! Got it.\n":
                print("OK! Got it.")
                for k in range(i, block_len):
                    Dct[k] ^= bytearray(chr(padding_num).encode())[0]   
                break
            else:
                Dct[i] ^= c
    
    iv = b""
    for i in range(16):
        iv += long_to_bytes(Dct[i] ^ 0x00)
    return iv

encrypted_flag = 67448907891721241368838325896320122397092733550961191069708016032244349188684070793897519352151466622385197077064799553157879456334546372809948272281247935498288157941438709402245513879910090372080411345199729220479271018326225319584057160895804120944126979515126944833368164622466123481816185794224793277249
N = 69214008498642035761243756357619851816607540327248468473247478342523127723748756926949706235406640562827724567100157104972969498385528097714986614165867074449238186426536742677816881849038677123630836686152379963670139334109846133566156815333584764063197379180877984670843831985941733688575703811651087495223
e = 65537

r = remote("10.113.184.121",10031)

random_key = os.urandom(16)
aes_ECB = AES.new(random_key, AES.MODE_ECB)
encrpto_key = asymmetric_encryption(random_key, N, e)


block_len = 1024 // 8 // 16
remainder = 0
counter = 1
flag = 0
mod = 2**128
mod_inv = pow(mod, -1, N)
mod_inv_e = pow(mod, -e, N)

# ans = bytes_to_long(b'o_oO_oO_o_oO_oO}')
# flag += ans * counter
# encrypted_flag = (encrypted_flag * mod_inv_e) % N
# remainder = (remainder + ans) * mod_inv % N
# counter *= mod 
# print(long_to_bytes(flag))

# ans = bytes_to_long(b'o_oO_oO_o_oO_oO_')
# flag += ans * counter
# encrypted_flag = (encrypted_flag * mod_inv_e) % N
# remainder = (remainder + ans) * mod_inv % N
# counter *= mod 
# print(long_to_bytes(flag))

# ans = bytes_to_long(b'e_oO_oO_o_oO_oO_')
# flag += ans * counter
# encrypted_flag = (encrypted_flag * mod_inv_e) % N
# remainder = (remainder + ans) * mod_inv % N
# counter *= mod 
# print(long_to_bytes(flag))

# ans = bytes_to_long(b'_oracle_of_oracl')
# flag += ans * counter
# encrypted_flag = (encrypted_flag * mod_inv_e) % N
# remainder = (remainder + ans) * mod_inv % N
# counter *= mod 
# print(long_to_bytes(flag))

# ans = bytes_to_long(b'o_Oo_Oo_Oo_Oo_Oo')
# flag += ans * counter
# encrypted_flag = (encrypted_flag * mod_inv_e) % N
# remainder = (remainder + ans) * mod_inv % N
# counter *= mod 
# print(long_to_bytes(flag))


# ans = bytes_to_long(b'Oo_Oo_Oo_Oo_Oo_O')
# flag += ans * counter
# encrypted_flag = (encrypted_flag * mod_inv_e) % N
# remainder = (remainder + ans) * mod_inv % N
# counter *= mod 
# print(long_to_bytes(flag))

# ans = bytes_to_long(b'{Oo_Oo_Oo_Oo_Oo_')
# flag += ans * counter
# encrypted_flag = (encrypted_flag * mod_inv_e) % N
# remainder = (remainder + ans) * mod_inv % N
# counter *= mod 
# print(long_to_bytes(flag))

while counter < pow(mod, block_len):
    iv = padding_oracle_attack(r, aes_ECB, encrpto_key, encrypted_flag)
    int_iv = bytes_to_long(iv)
    ans = (int_iv - remainder) % mod
    # print(long_to_bytes(ans))
    flag += ans * counter
    print(long_to_bytes(ans))

    encrypted_flag = (encrypted_flag * mod_inv_e) % N 
    remainder = (remainder + ans) * mod_inv % N
    counter *= mod 

print(long_to_bytes(flag))