## SOLUTION

The question has implemented simple registration and login system. Both encryption and decryption use AES-GCM mode, with fixed secret values for key and auth.

1. Register: The server randomly generates a username and sends the corresponding token to the user
2. Login: The user inputs a token, and the server verifies and decodes it to determine if the login was successful. If the logged in user is admin, return a flag.
3. Update: To prevent nonce reuse, each nonce is only allowed to be used twice and needs to be updated through Update.

According to the characteristics of AES-GCM mode, we can combine two sets of CT and tag pairs with the same nonce to recover H and E0 in AES-GCM. Based on this, we can construct effective tags for any CT.

Although there is auth here, in the case of the same number of plaintext blocks, auth can be merged with E0 into an additive offset, and we can construct tags based on this for ct with the same number of blocks.

If we log in again using the token of the question, we can obtain the corresponding username. Based on the characteristics of AES-GCM, we can construct valid tags for any username.

However, each nonce can only be used twice here, and we cannot reuse the same nonce. The above operation, including the last login, requires a total of 4 interactions. Therefore, another focus of the question is how to construct an equivalent nonce.

Looking at the source code of AES-GCM, it is found that although AES-GCM recommends using 12 byte nonce, any length of nonce can be accepted, roughly as follows:

```python
def INIT_COUNTER(nonce):
if len(nonce) % 12:
ctr = GHASH(pad128(nonce) + len64(nonce))
else:
ctr = nonce + long_to_bytes(1, 4)
return ctr
```

If we fix the length of the target nonce (e.g. 16), it is equivalent to finding the solution of GHASH (pad128 (nonce 1)+len64 (nonce 1))=nonce 0+long_to-bytes (1,4), which is easy to achieve. Based on this, we constructed two equivalent nonce, which can achieve the above attack with 4 interactions.



```
from sage.all import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad
from pwn import process, remote, context


z0 = GF(2)["z0"].gen()
F, z = GF(2**128, name="z", modulus=z0**128 + z0**7 + z0**2 + z0 + 1).objgen()

# basic tools
def xor(a, b):
    return bytes([ai^bi for ai, bi in zip(a, b)])

def pad128(pt):
    return pt + b'\x00' * ((16 - len(pt))%16)

def len64(pt):
    return long_to_bytes(len(pt)*8, 8)

def b2gf(b):
    return F(list(bin(bytes_to_long(b))[2:].zfill(128)))

def gf2b(g):
    return long_to_bytes(int(''.join(map(str, g.list())), 2), 16)


# io = process(["python", "main.py"])
io = remote("localhost", "9999")
# context.log_level = 'debug'
io.recvuntil(b"nonce = ")
nonce = bytes.fromhex(io.recvline().strip().decode())

io.sendlineafter(b'>', b'R')
io.recvuntil(b'Register!\n')
token1 = bytes.fromhex(io.recvline().strip().decode())

io.sendlineafter(b'>', b'R')
io.recvuntil(b'Register!\n')
token2 = bytes.fromhex(io.recvline().strip().decode())

auth = b"\x00"*16
ct1, tag1 = token1[:-16], token1[-16:]
ct2, tag2 = token2[:-16], token2[-16:]
C1 = pad128(auth) + pad128(ct1) + len64(auth) + len64(ct1)
C2 = pad128(auth) + pad128(ct2) + len64(auth) + len64(ct2)
C = xor(C1, C2)
x = F["x"].gen()

# H
f = 0
for i in range(0, len(C), 16):
    f += b2gf(C[i:i+16])
    f *= x
f -= b2gf(xor(tag1, tag2))
H = f.roots()[0][0]

# B
B = 0
for i in range(0, len(C1), 16):
    B += b2gf(C1[i:i+16])
    B *= H
B -= b2gf(tag1)

# nonce
ctr = nonce + long_to_bytes(1, 4)
f = x*H**2 + b2gf(len64(b'\x00'*16))*H + b2gf(ctr)
nonce = gf2b(f.roots()[0][0])

io.sendlineafter(b'>', b'U')
io.sendlineafter(b'nonce(hex)>', nonce.hex().encode())

io.sendlineafter(b'>', b'L')
io.sendlineafter(b'token(hex)>', token1.hex().encode())
io.recvuntil(b'Hello, what can I help you? ')
username1 = bytes.fromhex(io.recvline().strip().decode())

ct = xor(ct1, xor(pad(username1, 16), pad(b"admin", 16)))
C = pad128(auth) + pad128(ct) + len64(auth) + len64(ct)
tag = 0
for i in range(0, len(C), 16):
    tag += b2gf(C[i:i+16])
    tag *= H
tag += B
tag = gf2b(tag)
token = ct + tag

io.sendlineafter(b'>', b'L')
io.sendlineafter(b'token(hex)>', token.hex().encode())
print(f"{token.hex()}")
io.interactive()
```

