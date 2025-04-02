from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
BLOCK_SIZE = 16 # Bytes

key = get_random_bytes(BLOCK_SIZE)
cipher = AES.new(key, AES.MODE_ECB)
with open("flag.bmp", "rb") as fp:
    pt = fp.read()
ct = cipher.encrypt(pad(pt, BLOCK_SIZE))
with open("flag.enc","wb") as fp:
    fp.write(ct)
