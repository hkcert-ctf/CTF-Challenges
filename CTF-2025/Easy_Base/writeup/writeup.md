When encoding base64 letter by letter, f -> Zg==, l -> bA==, it can be observed that the encoding of the second letter is reversed. The same pattern can be seen for other letters

```py
from base64 import *

cipher = b'Zg====AbYQ====wZew====ARZQ====gbaQ====QcdQ====QZdQ====gYaQ====QZcg====QadA====wXcw====QYbg====wZdQ====Qacw====QYZw====AbYQ====AZaQ====wbcg====QZZw====Qacw====Qf'
flag = b''
for i in range(0, len(cipher), 8):
    chunk = cipher[i: i+8]
    chunk_even = chunk[0:4]
    flag += b64decode(chunk_even)
    chunk_odd = chunk[4:8][::-1]
    flag += b64decode(chunk_odd)

print(flag.decode())
```
