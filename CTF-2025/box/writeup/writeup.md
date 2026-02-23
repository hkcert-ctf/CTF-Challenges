First, navigate to the main function

```
__int64 sub_140009ED0()
{
  size_t v0; // rbx
  __int64 v1; // rdx
  __int64 v2; // r8
  __int64 v3; // rcx
  int v4; // eax
  FILE *v6; // rax
  __int64 v7; // r8
  size_t v8; // rax
  __int64 v9; // [rsp+20h] [rbp-1D8h] BYREF
  char v10; // [rsp+28h] [rbp-1D0h]
  _BYTE v11[48]; // [rsp+30h] [rbp-1C8h] BYREF
  char Buffer[48]; // [rsp+60h] [rbp-198h] BYREF
  __int64 v13; // [rsp+90h] [rbp-168h]
  __int64 v14; // [rsp+98h] [rbp-160h]
  __int64 v15; // [rsp+A0h] [rbp-158h]
  __int64 v16; // [rsp+A8h] [rbp-150h]
  __int64 v17; // [rsp+B0h] [rbp-148h]
  __int64 v18; // [rsp+B8h] [rbp-140h]
  __int64 v19; // [rsp+C0h] [rbp-138h]
  __int64 v20; // [rsp+C8h] [rbp-130h]
  __int64 v21; // [rsp+D0h] [rbp-128h]
  __int64 v22; // [rsp+D8h] [rbp-120h]
  _BYTE v23[280]; // [rsp+E0h] [rbp-118h] BYREF

  v0 = 0;
  sub_1400021F7();
  v1 = 0;
  v2 = 1;
  v3 = 0;
  memset(Buffer, 0, sizeof(Buffer));
  v13 = 0;
  v14 = 0;
  v15 = 0;
  v16 = 0;
  v17 = 0;
  v18 = 0;
  v19 = 0;
  v20 = 0;
  v21 = 0;
  v22 = 0;
  while ( 1 )
  {
    v4 = (unsigned __int8)(95 * v3 + 29);
    if ( v4 == 124 )
      goto LABEL_37;
    if ( (unsigned __int8)(95 * v3 + 29) > 0x7Cu )
    {
      if ( v4 == 219 )
        goto LABEL_38;
      if ( (unsigned __int8)(95 * v3 + 29) > 0xDBu )
      {
        if ( v4 == 240 )
          goto LABEL_33;
        if ( v4 != 248 )
          return 0;
      }
      else
      {
        if ( v4 == 182 )
          goto LABEL_13;
        if ( v4 == 211 )
          goto LABEL_16;
        if ( v4 != 153 )
          return 0;
LABEL_9:
        if ( (unsigned int)sub_1400017E0(v3, v1, v2) )
        {
          v10 = -103;
          v9 = 0x24F5B91F7D51F399LL;
        }
        else
        {
          sub_1400018E0(&v9);
        }
      }
      qmemcpy(v11, Buffer, 0x2Au);
      goto LABEL_12;
    }
    if ( v4 == 58 )
      goto LABEL_41;
    if ( (unsigned __int8)(95 * v3 + 29) > 0x3Au )
    {
      if ( v4 != 87 )
      {
        if ( v4 != 116 )
          return 0;
LABEL_15:
        sub_140001E70(v11, 42);
LABEL_16:
        v2 = 1;
        v3 = 11;
        LODWORD(v1) = 0;
        goto LABEL_17;
      }
LABEL_12:
      sub_140001B10(v11, 42);
LABEL_13:
      sub_140001B90(v23, &v9, 9);
LABEL_14:
      sub_140001D30(v23, v11, 42);
      goto LABEL_15;
    }
    if ( v4 == 29 )
      break;
    if ( v4 != 50 )
    {
      if ( v4 != 21 )
        return 0;
      goto LABEL_14;
    }
    if ( (_DWORD)v1 == 42 )
      goto LABEL_33;
LABEL_17:
    if ( v11[(int)v1] != byte_14000C0A0[(int)v1] )
    {
      v2 = 0;
LABEL_33:
      if ( (_DWORD)v2 )
        sub_140001EE0(&unk_14000B090, 26, v2);
      else
        sub_140001EE0(&unk_14000B080, 7, v2);
      putchar(10);
      return 0;
    }
    v1 = (unsigned int)(v1 + 1);
  }
  sub_140001EE0(&unk_14000B0C0, 16, 1);
LABEL_37:
  v6 = (FILE *)off_14000B1F0();
  if ( fgets(Buffer, 128, v6) )
  {
LABEL_38:
    v8 = strlen(Buffer);
    v0 = v8;
    if ( v8 && v11[v8 + 47] == 10 )
    {
      v11[v8 + 47] = 0;
      v0 = v8 - 1;
    }
LABEL_41:
    if ( v0 != 42 )
    {
      sub_140001EE0(&unk_14000B080, 7, v2);
      putchar(10);
      return 1;
    }
    goto LABEL_9;
  }
  sub_140001EE0(&unk_14000B0B0, 12, v7);
  putchar(10);
  return 1;
}
```



```
_BOOL8 check_dbg()
{
  HANDLE CurrentProcess; // rax
  DWORD TickCount; // eax
  int v3; // edx
  DWORD v4; // ebx
  int v5; // eax
  BOOL pbDebuggerPresent; // [rsp+38h] [rbp-10h] BYREF
  int v7; // [rsp+3Ch] [rbp-Ch]

  if ( IsDebuggerPresent() )
    return 1;
  pbDebuggerPresent = 0;
  CurrentProcess = GetCurrentProcess();
  CheckRemoteDebuggerPresent(CurrentProcess, &pbDebuggerPresent);
  if ( pbDebuggerPresent )
    return 1;
  TickCount = GetTickCount();
  v7 = 0;
  v3 = 0;
  v4 = TickCount;
  do
  {
    v5 = v3 + v7;
    ++v3;
    v7 = v5;
  }
  while ( v3 != 10000 );
  return GetTickCount() - v4 > 0x32
      || GetModuleHandleA("ida.dll")
      || GetModuleHandleA("ida64.dll")
      || GetModuleHandleA("x64dbg.dll")
      || GetModuleHandleA("x32dbg.dll") != 0;
}
```

![image-20251205123759407](img\image-20251205123759407.png)





![](img\image-20251205121051018.png)

```
unsigned char ida_chars[] =
{
0x99, 0x51, 0xD7, 0x1A, 0x65, 0xCA, 0x12, 0xAB, 0x12, 0x13,
0xB2, 0xA4, 0x90
};
```

Analysis shows that the key only needs to be 9 bytes

```
0x99, 0x51, 0xD7, 0x1A, 0x65, 0xCA, 0x12, 0xAB, 0x12
```

The rest is to analyze the modified RC4 algorithm

```
__int64 __fastcall sub_140001E70(__int64 a1, int a2)
{
  __int64 result; // rax
  int i; // ebx
  __int64 v6; // rdi
  char v7; // al
  char v8; // dl
  __int64 v9; // rcx

  result = 17;
  for ( i = 0; a2 > i; result = 64 )
  {
    v6 = i;
    v7 = 91 * i;
    v8 = 16 * i;
    v9 = *(unsigned __int8 *)(a1 + i++);
    *(_BYTE *)(a1 + v6) = off_14000B030(v9, (unsigned __int8)((v7 - 89) ^ v8));
  }
  return result;
}
```

modified KSA

sub_140001B90

```
__int64 __fastcall sub_140001B90(__int64 a1, __int64 a2, int a3)
{
  __m128i si128; // xmm2
  __m128i v4; // xmm9
  __m128i v5; // xmm5
  __m128i v6; // xmm8
  __m128i v7; // xmm7
  __m128i v8; // xmm6
  __int64 result; // rax
  __m128i v13; // xmm3
  __m128i v14; // xmm0
  __m128i v15; // xmm4
  __m128i v16; // xmm3
  __m128i v17; // xmm1
  __m128i v18; // xmm3
  __m128i v19; // xmm0
  __m128i v20; // xmm1
  __m128i v21; // xmm3
  __m128i v22; // xmm0
  __m128i v23; // xmm3
  int v24; // edi
  unsigned __int8 v25; // bl
  __int64 (__fastcall *v26)(); // r14
  __int64 v27; // rbp
  unsigned int v28; // ecx
  int v29; // eax
  unsigned __int8 v30; // al
  __int64 v31; // rcx
  char *v32; // rbp
  unsigned __int8 v33; // al
  char v34; // dl

  si128 = _mm_load_si128((const __m128i *)&xmmword_14000C1F0);
  v4 = _mm_shuffle_epi32(_mm_cvtsi32_si128(4u), 0);
  v5 = _mm_srli_epi16((__m128i)-1LL, 8u);
  v6 = _mm_shuffle_epi32(_mm_cvtsi32_si128(8u), 0);
  v7 = _mm_shuffle_epi32(_mm_cvtsi32_si128(0xCu), 0);
  v8 = _mm_shuffle_epi32(_mm_cvtsi32_si128(0x10u), 0);
  result = a1;
  do
  {
    result += 16;
    v13 = _mm_add_epi32(si128, v4);
    v14 = _mm_unpackhi_epi16(si128, v13);
    v15 = _mm_add_epi32(si128, v7);
    v16 = _mm_unpacklo_epi16(si128, v13);
    v17 = _mm_unpacklo_epi16(v16, v14);
    v18 = _mm_unpackhi_epi16(v16, v14);
    v19 = si128;
    si128 = _mm_add_epi32(si128, v8);
    v20 = _mm_unpacklo_epi16(v17, v18);
    v21 = _mm_add_epi32(v19, v6);
    v22 = _mm_unpacklo_epi16(v21, v15);
    v23 = _mm_unpackhi_epi16(v21, v15);
    *(__m128i *)(result - 16) = _mm_packus_epi16(
                                  _mm_and_si128(v20, v5),
                                  _mm_and_si128(
                                    _mm_unpacklo_epi16(_mm_unpacklo_epi16(v22, v23), _mm_unpackhi_epi16(v22, v23)),
                                    v5));
  }
  while ( a1 + 256 != result );
  v24 = 0;
  v25 = 0;
  while ( v24 != 256 )
  {
    v26 = off_14000B020[0];
    v27 = v24;
    v28 = (unsigned __int8)off_14000B030();
    v29 = v24++;
    v30 = ((__int64 (__fastcall *)(_QWORD, _QWORD))v26)(*(unsigned __int8 *)(a2 + v29 % a3), v28);
    v31 = *(unsigned __int8 *)(a1 + v27);
    v32 = (char *)(a1 + v27);
    v33 = ((__int64 (__fastcall *)(__int64, _QWORD))v26)(v31, v30);
    LOBYTE(result) = ((__int64 (__fastcall *)(_QWORD, _QWORD))v26)(v25, v33);
    v34 = *v32;
    v25 = result;
    result = (unsigned __int8)result;
    *v32 = *(_BYTE *)(a1 + (unsigned __int8)result);
    *(_BYTE *)(a1 + (unsigned __int8)result) = v34;
  }
  return result;
}
```



PRGA

```
__int64 __fastcall sub_140001D30(__int64 a1, __int64 a2, int a3)
{
  unsigned __int8 v3; // di
  unsigned __int8 v4; // si
  __int64 result; // rax
  int i; // ebx
  __int64 v10; // r13
  __int64 v11; // r15
  char v12; // dl
  __int64 (__fastcall *v13)(); // r15
  unsigned __int8 v14; // al
  unsigned __int8 v15; // [rsp+2Fh] [rbp-49h]

  v3 = 0;
  v4 = 0;
  result = 0;
  for ( i = 0; a3 > i; ++i )
  {
    v10 = (unsigned __int8)off_14000B020(v4, 1);
    v4 = v10;
    v11 = (unsigned __int8)off_14000B020(v3, *(unsigned __int8 *)(a1 + v10));
    v12 = *(_BYTE *)(a1 + v10);
    v3 = v11;
    *(_BYTE *)(a1 + v10) = *(_BYTE *)(a1 + v11);
    *(_BYTE *)(a1 + v11) = v12;
    if ( (~(_BYTE)i & 7) == 0 )
      *(_BYTE *)(a1 + v10) = off_14000B020(*(unsigned __int8 *)(a1 + v10), *(unsigned __int8 *)(a1 + v11));
    off_14000B020(*(unsigned __int8 *)(a1 + v10), *(unsigned __int8 *)(a1 + v11));
    v13 = off_14000B030;
    v15 = off_14000B030();
    v14 = off_14000B030();
    *(_BYTE *)(a2 + i) = ((__int64 (__fastcall *)(_QWORD, _QWORD))v13)(v14, v15);
    result = 1;
  }
  return result;
}
```



sub_140001B10

```
void __fastcall sub_140001B10(__int64 a1, int a2)
{
  int i; // ebx
  _BYTE *v5; // rbp
  unsigned __int8 v6; // al
  __int64 v7; // rcx
  unsigned __int8 v8; // al

  for ( i = 0; a2 > i; *v5 = off_14000B030(v7, v8) )
  {
    v5 = (_BYTE *)(a1 + i);
    v6 = off_14000B030((unsigned __int8)*v5, 60);
    off_14000B020(v6, (unsigned __int8)i);
    v7 = (unsigned __int8)off_14000B070();
    v8 = 55 * i++;
  }
}
```

ciphertext data

![image-20251205122706920](img\image-20251205122706920.png)

```
unsigned char ida_chars[] =
{
  0xA9, 0xBB, 0x6C, 0xD0, 0x58, 0xE8, 0x45, 0x88, 0xD7, 0x73, 
  0x5B, 0x6A, 0xEB, 0x12, 0x67, 0x15, 0xEE, 0xFE, 0xDD, 0x44, 
  0x93, 0x1E, 0x5D, 0xB6, 0xFA, 0x3D, 0xAF, 0x75, 0xD6, 0x29, 
  0x4F, 0x48, 0x24, 0xDB, 0xC6, 0x30, 0x5A, 0x35, 0xD2, 0xED, 
  0x79, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
```



The decryption script is

```
def ADD(a, b):
    return (a + b) & 0xFF

def XOR(a, b):
    return a ^ b

def ROR1(val, n):
    n = n & 7
    return ((val >> n) | (val << (8 - n))) & 0xFF

ciphertext = [
    0xa9, 0xbb, 0x6c, 0xd0, 0x58, 0xe8, 0x45, 0x88,
    0xd7, 0x73, 0x5b, 0x6a, 0xeb, 0x12, 0x67, 0x15,
    0xee, 0xfe, 0xdd, 0x44, 0x93, 0x1e, 0x5d, 0xb6,
    0xfa, 0x3d, 0xaf, 0x75, 0xd6, 0x29, 0x4f, 0x48,
    0x24, 0xdb, 0xc6, 0x30, 0x5a, 0x35, 0xd2, 0xed,
    0x79, 0x43
]

key = [0x99, 0x51, 0xD7, 0x1A, 0x65, 0xCA, 0x12, 0xAB, 0x12]

def reverse_post_process(data):
    result = data[:]
    for i in range(len(result)):
        result[i] = XOR(result[i], (((91 * i) - 89) ^ (16 * i)) & 0xFF)
    return result

def rc4_ksa_modified(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        v = ADD(XOR(i, 0x5A), key[i % len(key)])
        j = ADD(j, ADD(S[i], v))
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga_modified_decrypt(S, data):
    S = S[:]
    result = data[:]
    i_idx = j_idx = 0
    for idx in range(len(data)):
        i_idx = ADD(i_idx, 1)
        j_idx = ADD(j_idx, S[i_idx])
        S[i_idx], S[j_idx] = S[j_idx], S[i_idx]
        if (~idx & 7) == 0:
            S[i_idx] = ADD(S[i_idx], S[j_idx])
        keystream = S[ADD(S[i_idx], S[j_idx])]
        result[idx] = XOR(XOR(data[idx], XOR(0x5A, idx)), keystream)
    return result

def reverse_pre_process(data):
    result = data[:]
    for i in range(len(result)):
        tmp3 = XOR(result[i], (0x37 * i) & 0xFF)
        tmp2 = ROR1(tmp3, 3)
        tmp1 = (tmp2 - i) & 0xFF
        result[i] = XOR(tmp1, 0x3C)
    return result

step1 = reverse_post_process(ciphertext)
S = rc4_ksa_modified(key)
step3 = rc4_prga_modified_decrypt(S, step1)
plaintext = reverse_pre_process(step3)
print(bytes(plaintext).decode())


```

