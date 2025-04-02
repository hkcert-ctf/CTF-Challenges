from lzma import compress
from tqdm import tqdm
import random
print("Flag Encrypter")
print("==============")
while True:
    raw_flag = input("Enter the Flag: ").encode()
    if b"\0" in raw_flag:
        print("Only non-null characters are allowed!\n")
        continue
    else:
        raw_flag += b"\0"
        while len(raw_flag) % 6 != 0:
            raw_flag += b"\0"
        flag = b""
        # some integrity marks
        for i in range(0, len(raw_flag), 6):
            flag += raw_flag[i:i+6] + b"\xff\xff"
        while len(flag) < 960 or len(flag) % 8 != 0:
            if len(flag) % 8 >= 6:
                flag += b"\xff"
            else:
                flag += bytes([random.randrange(1, 255)])
        block = bytes([random.randrange(256) for _ in range(8)])
        processed = [block.hex()]
        last = block
        # preserve the links to the previous elements
        for i in tqdm(range(0, len(flag), 8)):
            block = compress(last + flag[i:i+8], preset=9)[-28:-20]
            processed.append(block.hex())
            last = block
        processed.sort(key = lambda _: random.random())
        print("Result:", "".join(processed))
