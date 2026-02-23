* **题目名称：** onebyone
* **Writeup：** 

```python
arr=[206, 176, 51, 89, 115, 30, 199, 248, 5, 103, 255, 154, 27, 21, 228, 69, 190, 160, 235, 131, 5, 16, 112, 22]
#RC4 decryption
c=arr
t=[]
key='hswSss]e'
ch=[]
j=0
s=list(range(256))
for i in range(256):
    j=(j+s[i]+ord(key[i%len(key)]))%256
    s[i],s[j]=s[j],s[i]
i=0
j=0
for r in c:
    i=(i+2)%256
    j=(j+s[i])%256
    s[i],s[j]=s[j],s[i]
    x=((s[i]+s[j]+2))%256
    ch.append((r^s[x]))
print(ch)

#crc32 decryption
a=[
    0x42a498d7834d9485,0x6ee68e605a16d31,0x15109fc695020a8c
]
key=0x72F9E1EBA0EA3693
arr3=[
    0x42a498d7834d9485
]
a=[]
for j in range(1):
    t=arr3[j]
    for i in range(64):
        if t&1==1:
            t=(t^key)//2
            t |= 0x8000000000000000   #set high bit to 1
        else:
            t=t//2
    a.append(hex(t))
print(a)
```

