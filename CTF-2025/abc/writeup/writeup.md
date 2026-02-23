## abc

The question provides a file with a suffix of bc, which is an intermediate file from C code to an executable file

There are two methods to solve the problem

1. By using llvm-dis to decompile the ll file from the previous stage, we obtain a text file that is partially readable
   llvm-dis a.bc -o a.ll
2. Continue to compile the bc file into an executable file, and then analyze it using IDA
   clang a.bc -o a

The following is the result of decompiling the executable file using IDA

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rcx
  _WORD *v4; // rax
  void *s1; // [rsp+8h] [rbp-148h]
  char v7[256]; // [rsp+10h] [rbp-140h] BYREF
  void *v8; // [rsp+110h] [rbp-40h]
  size_t v9; // [rsp+118h] [rbp-38h]
  void *v10; // [rsp+120h] [rbp-30h]
  int v11; // [rsp+12Ch] [rbp-24h]
  void *ptr; // [rsp+130h] [rbp-20h]
  size_t n; // [rsp+138h] [rbp-18h]
  size_t size; // [rsp+140h] [rbp-10h]
  int v15; // [rsp+14Ch] [rbp-4h]

  v15 = 0;
  size = 1024LL;
  n = 0LL;
  ptr = malloc(0x400uLL);
  if ( ptr )
  {
    while ( 1 )
    {
      v11 = getchar();
      if ( v11 == 10 )
        break;
      if ( n == size )
      {
        size *= 2LL;
        v10 = realloc(ptr, size);
        if ( !v10 )
        {
          free(ptr);
          fprintf(stderr, "realloc failed\n");
          return 1;
        }
        ptr = v10;
      }
      v3 = n++;
      *((_BYTE *)ptr + v3) = v11;
    }
    v9 = n + 10;
    v8 = malloc(n + 10);
    if ( v8 )
    {
      v4 = v8;
      *(_QWORD *)v8 = sub_138;
      v4[4] = 32101;
      if ( n )
        memcpy((char *)v8 + 10, ptr, n);
      sub_2a4c(v7, "ab#_var1an&_k3y_f0r_???", 23LL);
      s1 = malloc(v9);
      if ( s1 )
      {
        sub_1a4c(v7, v8, s1, v9);
        if ( v9 == 42 )
        {
          if ( !memcmp(s1, &sub_584c, 0x2AuLL) )
            printf("Correct!\n");
          else
            printf("Incorrect!\n");
          free(ptr);
          free(v8);
          free(s1);
          return 0;
        }
        else
        {
          printf("Incorrect! (length mismatch)\n");
          free(ptr);
          free(v8);
          free(s1);
          return 0;
        }
      }
      else
      {
        free(ptr);
        free(v8);
        fprintf(stderr, "malloc failed\n");
        return 1;
      }
    }
    else
    {
      free(ptr);
      fprintf(stderr, "malloc failed\n");
      return 1;
    }
  }
  else
  {
    fprintf(stderr, "malloc failed\n");
    return 1;
  }
}
__int64 __fastcall sub_2a4c(__int64 a1, __int64 a2, unsigned __int64 a3)
{
  __int64 result; // rax
  char v4; // [rsp+Ah] [rbp-26h]
  int j; // [rsp+Ch] [rbp-24h]
  char v6; // [rsp+13h] [rbp-1Dh]
  unsigned __int8 v7; // [rsp+13h] [rbp-1Dh]
  int i; // [rsp+14h] [rbp-1Ch]

  for ( i = 0; i < 256; ++i )
  {
    *(_BYTE *)(a1 + i) = i;
    result = (unsigned int)(i + 1);
  }
  v6 = 0;
  for ( j = 0; j < 256; ++j )
  {
    v7 = *(_BYTE *)(a2 + (5 * j + 3) % a3) + *(_BYTE *)(a1 + j) + v6;
    v4 = *(_BYTE *)(a1 + j);
    *(_BYTE *)(a1 + j) = *(_BYTE *)(a1 + v7);
    *(_BYTE *)(a1 + v7) = v4;
    v6 = j + v7;
    result = (unsigned int)(j + 1);
  }
  return result;
}
unsigned __int64 __fastcall sub_1a4c(__int64 a1, __int64 a2, __int64 a3, unsigned __int64 a4)
{
  unsigned __int64 result; // rax
  char v5; // [rsp+3h] [rbp-31h]
  unsigned __int64 i; // [rsp+4h] [rbp-30h]
  unsigned __int8 v7; // [rsp+12h] [rbp-22h]
  unsigned __int8 v8; // [rsp+13h] [rbp-21h]

  v8 = 0;
  v7 = 0;
  for ( i = 0LL; ; ++i )
  {
    result = i;
    if ( i >= a4 )
      break;
    ++v8;
    v7 += v8 + *(_BYTE *)(a1 + v8);
    v5 = *(_BYTE *)(a1 + v8);
    *(_BYTE *)(a1 + v8) = *(_BYTE *)(a1 + v7);
    *(_BYTE *)(a1 + v7) = v5;
    *(_BYTE *)(a3 + i) = *(_BYTE *)(a1
                                  + (unsigned __int8)(v8
                                                    + *(_BYTE *)(a1
                                                               + (unsigned __int8)(*(_BYTE *)(a1 + v7)
                                                                                 + *(_BYTE *)(a1 + v8))))) ^ *(_BYTE *)(a2 + i);
  }
  return result;
}
```

The encryption logic is similar to RC4, but it is a variant
1. KSA: 
	1. `(i*5+3) % keylen`
	2. `j = (j + i) % 256`
2. PRGA: 
	1. `j = (j + S[i] + i) % 256`
	2. `t = (S[(S[i]+S[j])%256] + i)`

The problem-solving script is as follows:
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List

CIPHERTEXT_HEX = "c2f6bfa99abe24dc680cf460d7faca2c58ca3808892f40245d879792a25bfa81ba598070b6648253115d"
KEY = b"ab#_var1an&_k3y_f0r_???"
SALT = b"flag{fake}"

def ksa_variant(key: bytes) -> List[int]:
    S = list(range(256))
    j = 0
    keylen = len(key)
    for i in range(256):
        ki = key[(i * 5 + 3) % keylen]
        j = (j + S[i] + ki) & 0xFF
        S[i], S[j] = S[j], S[i]
        j = (j + i) & 0xFF
    return S

def prga_keystream(S: List[int], length: int) -> bytes:
    i = 0
    j = 0
    out = bytearray()
    for _ in range(length):
        i = (i + 1) & 0xFF
        j = (j + S[i] + i) & 0xFF
        S[i], S[j] = S[j], S[i]
        t = (S[(S[i] + S[j]) & 0xFF] + i) & 0xFF
        k = S[t]
        out.append(k)
    return bytes(out)

def hex_to_bytes(s: str) -> bytes:
    s = s.strip()
    s = s.replace(" ", "").replace("\n", "")
    return bytes.fromhex(s)

def main():
    ct = hex_to_bytes(CIPHERTEXT_HEX)

    S = ksa_variant(KEY)
    ks = prga_keystream(S, len(ct))
    salted_plain = bytes(c ^ k for c, k in zip(ct, ks))

    plaintext = salted_plain[len(SALT):]
    print(plaintext)

if __name__ == "__main__":
    main()
```

