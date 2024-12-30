from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import long_to_bytes
from random import randbytes
import os
from PIL import Image
from io import BytesIO

def unpad(c):
    length = c[-1]
    for char in c[-length:]:
        if char != length:
            raise ValueError
    return c[:-length]


def asymmetric_encryption(message, N, e):
    padded_message = randbytes(100) + message
    return pow(bytes_to_long(padded_message), e, N)

def sendmsg(r, key, iv, ct):
    r.sendlineafter(b'key: ', str(key).encode())
    r.sendlineafter(b'iv: ', str(iv).encode())
    r.sendlineafter(b'ciphertext: ', ct.hex().encode())

def padding_oracle_attack(r, aes_ECB, encrpto_key, encrpto_iv):
    # Dct = bytearray(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    # IV's Dct
    Dct = bytearray(b"\x5b\xac\xc5\x11\x1f\x4d\x5b\xca\xb3\x5b\xd0\xe6\x85\xc1\x92\x9a")
    # Key's Dct
    # Dct = bytearray(b"\x59\x28\x63\x52\x38\x54\x3f\x7d\x7a\x37\x68\x3c\x5b\x68\x31\x78")

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
    
    
    return Dct
        

r = remote("10.113.184.121", 10031)
N = 69214008498642035761243756357619851816607540327248468473247478342523127723748756926949706235406640562827724567100157104972969498385528097714986614165867074449238186426536742677816881849038677123630836686152379963670139334109846133566156815333584764063197379180877984670843831985941733688575703811651087495223
e = 65537
encrypted_key = 65690013242775728459842109842683020587149462096059598501313133592635945234121561534622365974927219223034823754673718159579772056712404749324225325531206903216411508240699572153162745754564955215041783396329242482406426376133687186983187563217156659178000486342335478915053049498619169740534463504372971359692
encrypted_iv = 35154524936059729204581782839781987236407179504895959653768093617367549802652967862418906182387861924584809825831862791349195432705129622783580000716829283234184762744224095175044663151370869751957952842383581513986293064879608592662677541628813345923397286253057417592725291925603753086190402107943880261658
cipher_flag = open("encrypted_flag.not_png", "rb").read()
block_num = len(cipher_flag) // 16
# print("cipher_flag[0:16] = ", cipher_flag[0:16])



random_key = os.urandom(16)
aes_ECB = AES.new(random_key, AES.MODE_ECB)
encrpto_key = asymmetric_encryption(random_key, N, e)

decrypted_iv = padding_oracle_attack(r, aes_ECB, encrpto_key, encrypted_iv)
# decrypted_iv = b'K\xa3\xcb\x1c\x13FQ\xc3\xbb\\\xd6\xe3\x81\xc2\x90\x9b'
print(decrypted_iv)
decrypted_key = padding_oracle_attack(r, aes_ECB, encrpto_key, encrypted_key)
# decrypted_key = b"I'm_4_5tr0n9_k3y"
print(decrypted_key)


flag=b""
cipher = AES.new(decrypted_key, AES.MODE_CBC, decrypted_iv) 
flag = unpad(cipher.decrypt(cipher_flag[:]))
print(flag)
img = Image.open(BytesIO(flag))
img.save("Oracle.png")


