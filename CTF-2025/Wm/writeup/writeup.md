Contestants need to use Ghidra with plugins to decompile wasm files

```

uint export::check(int param1,uint param2)

{
  char cVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  byte bVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  int iVar10;
  undefined4 uVar11;
  uint uVar12;
  byte *pbVar13;
  byte local_160 [16];
  byte local_150;
  byte local_a0;
  byte local_9f;
  byte local_9e;
  byte local_9d;
  undefined1 uStack_9c;
  byte local_9b;
  byte local_9a;
  byte local_99;
  undefined1 uStack_98;
  byte local_97;
  byte local_96;
  byte local_95;
  undefined1 uStack_94;
  byte local_93;
  byte local_92;
  byte local_91;
  byte local_90;
  byte local_50;
  byte local_10;
  byte local_8 [8];

  uVar8 = 0;
  uVar9 = 0;
  uVar12 = 0;
  if (param2 < 0x31) {
    for (; uVar9 != 8; uVar9 = uVar9 + 1) {
      uVar11 = unnamed_function_2((uint)*(byte *)(uVar9 + 0x400),(uint)*(byte *)(uVar9 + 0x410),
                                  uVar9 & 0xff);
      (&local_10)[uVar9] = (byte)uVar11;
    }
    for (uVar9 = 8; uVar9 != 0x10; uVar9 = uVar9 + 1) {
      uVar11 = unnamed_function_2((uint)*(byte *)(uVar9 + 0x400),(uint)*(byte *)(uVar9 + 0x410),
                                  uVar9 & 0xff);
      (&local_10)[uVar9] = (byte)uVar11;
    }
    uVar9 = (param2 & 0x30) + 0x10;
    for (; param2 != uVar12; uVar12 = uVar12 + 1) {
      (&local_50)[uVar12] = *(byte *)(param1 + uVar12);
    }
    uVar12 = uVar9;
    if (uVar9 <= param2) {
      uVar12 = param2;
    }
    cVar1 = (char)param2;
    for (; param2 != uVar12; param2 = param2 + 1) {
      (&local_50)[param2] = (char)uVar9 - cVar1;
    }
    if (uVar9 == 0x20) {
      for (uVar8 = 0; uVar8 < 0x20; uVar8 = uVar8 + 0x10) {
        for (iVar7 = 0; iVar7 != 0x10; iVar7 = iVar7 + 1) {
          (&local_a0)[iVar7] = (&local_50)[iVar7 + uVar8];
        }
        for (iVar7 = 0; iVar7 != 0x10; iVar7 = iVar7 + 1) {
          (&local_150)[iVar7] = (&local_10)[iVar7];
        }
        for (iVar7 = 1; iVar7 != 0xb; iVar7 = iVar7 + 1) {
          for (iVar10 = 0; iVar10 != 0x10; iVar10 = iVar10 + 1) {
            (&local_150)[iVar10 + iVar7 * 0x10] =
                 (char)iVar7 * '\x11' ^ local_160[iVar10 + iVar7 * 0x10] ^ (byte)iVar10;
          }
        }
        unnamed_function_3(&local_a0,&local_150);
        for (iVar7 = 1; iVar7 != 0xb; iVar7 = iVar7 + 1) {
          for (iVar10 = 0; bVar6 = local_91, bVar5 = local_97, bVar4 = local_9a, bVar3 = local_9e,
              bVar2 = local_9f, iVar10 != 0x10; iVar10 = iVar10 + 1) {
            pbVar13 = &local_a0 + iVar10;
            *pbVar13 = *(byte *)(*pbVar13 + 0x420);
          }
          local_9f = local_9b;
          local_97 = local_93;
          local_9b = bVar5;
          local_93 = bVar2;
          local_9e = local_96;
          local_96 = bVar3;
          local_9a = local_92;
          local_92 = bVar4;
          local_91 = local_95;
          local_95 = local_99;
          local_99 = local_9d;
          local_9d = bVar6;
          if (iVar7 != 10) {
            unnamed_function_4(&local_a0);
            unnamed_function_4(&uStack_9c);
            unnamed_function_4(&uStack_98);
            unnamed_function_4(&uStack_94);
          }
          unnamed_function_3(&local_a0,&local_150 + iVar7 * 0x10);
        }
        for (iVar7 = 0; iVar7 != 0x10; iVar7 = iVar7 + 1) {
          (&local_90)[iVar7 + uVar8] = (&local_a0)[iVar7];
        }
      }
      uVar8 = 0;
      do {
        uVar9 = uVar8;
        if (uVar9 == 0x20) break;
        uVar8 = uVar9 + 1;
      } while ((&local_90)[uVar9] == *(byte *)(uVar9 + 0x520));
      uVar8 = (uint)(0x1f < uVar9);
    }
  }
  return uVar8;
}


```

You can tell from the name that this is the checking function

```
if (param2 < 0x31) {  // len < 49
```



Key Recovery

```

for (; uVar9 != 8; uVar9 = uVar9 + 1) {
    uVar11 = unnamed_function_2(
        *(byte *)(uVar9 + 0x400),    // key_data[i]
        *(byte *)(uVar9 + 0x410),    // key_transform[i]
        uVar9 & 0xff                  // i
    );
    (&local_10)[uVar9] = (byte)uVar11;
}

```

```
uint8_t decode_key_byte(uint8_t encoded, uint8_t transform, uint8_t idx) {
    uint8_t tmp = encoded ^ transform;
    tmp = (tmp - (idx * 0x17)) & 0xFF;
    return tmp;
}
```

PKCS7 Padding

```
uVar9 = (param2 & 0x30) + 0x10;  // plen = ((len / 16) + 1) * 16
for (; param2 != uVar12; uVar12 = uVar12 + 1) {
    (&local_50)[uVar12] = *(byte *)(param1 + uVar12);  // copy input
}
for (; param2 != uVar12; param2 = param2 + 1) {
    (&local_50)[param2] = (char)uVar9 - cVar1;  // padding value = plen - len
}
```

Key Expansion

```
for (iVar7 = 1; iVar7 != 0xb; iVar7 = iVar7 + 1) {
    for (iVar10 = 0; iVar10 != 0x10; iVar10 = iVar10 + 1) {
        (&local_150)[iVar10 + iVar7 * 0x10] =
             (char)iVar7 * '\x11' ^ local_160[...] ^ (byte)iVar10;
    }
}
```

AES Round Function

```
// SubBytes
*pbVar13 = *(byte *)(*pbVar13 + 0x420);

// ShiftRows
local_9f = local_9b; local_97 = local_93; ...

// MixColumns
if (iVar7 != 10) {
    unnamed_function_4(&local_a0);    // aes_mix_single_column
    unnamed_function_4(&uStack_9c);
    ...
}

// AddRoundKey
unnamed_function_3(&local_a0, &local_150 + iVar7 * 0x10);
```

Ciphertext Comparison

```
do {
    if (uVar9 == 0x20) break;
    uVar8 = uVar9 + 1;
} while ((&local_90)[uVar9] == *(byte *)(uVar9 + 0x520));  // target_bytes
uVar8 = (uint)(0x1f < uVar9);  // return 1 on success
```

Now we need to extract data from addresses 0x400 0x410 0x420 0x520

![image.png](img\1764922716642-34268bc4-4858-4833-bf89-34573c24b41b.png)

```
    ram:00000400 80              ??         80h
    ram:00000401 80              ??         80h
    ram:00000402 58              ??         58h    X
    ram:00000403 4b              ??         4Bh    K
    ram:00000404 c6              ??         C6h
    ram:00000405 16              ??         16h
    ram:00000406 5e              ??         5Eh    ^
    ram:00000407 90              ??         90h
    ram:00000408 95              ??         95h
    ram:00000409 b5              ??         B5h
    ram:0000040a 36              ??         36h    6
    ram:0000040b aa              ??         AAh
    ram:0000040c 5e              ??         5Eh    ^
    ram:0000040d 54              ??         54h    T
    ram:0000040e fe              ??         FEh
    ram:0000040f 9a              ??         9Ah
    ram:00000410 ab              ??         ABh
    ram:00000411 cd              ??         CDh
    ram:00000412 17              ??         17h
    ram:00000413 39              ??         39h    9
    ram:00000414 5e              ??         5Eh    ^
    ram:00000415 82              ??         82h
    ram:00000416 f1              ??         F1h
    ram:00000417 4a              ??         4Ah    J
    ram:00000418 63              ??         63h    c
    ram:00000419 b7              ??         B7h
    ram:0000041a 2c              ??         2Ch    ,
    ram:0000041b 90              ??         90h
    ram:0000041c d5              ??         D5h
    ram:0000041d 08              ??         08h
    ram:0000041e 7f              ??         7Fh
    ram:0000041f e6              ??         E6h

```





```
    ram:00000420 39              ??         39h    9
    ram:00000421 26              ??         26h    &
    ram:00000422 2d              ??         2Dh    -
    ram:00000423 21              ??         21h    !
    ram:00000424 a8              ??         A8h
    ram:00000425 31              ??         31h    1
    ram:00000426 35              ??         35h    5
    ram:00000427 9f              ??         9Fh
    ram:00000428 6a              ??         6Ah    j
    ram:00000429 5b              ??         5Bh    [
    ram:0000042a 3d              ??         3Dh    =
    ram:0000042b 71              ??         71h    q
    ram:0000042c a4              ??         A4h
    ram:0000042d 8d              ??         8Dh
    ram:0000042e f1              ??         F1h
    ram:0000042f 2c              ??         2Ch    ,
    ram:00000430 90              ??         90h
    ram:00000431 d8              ??         D8h
    ram:00000432 93              ??         93h
    ram:00000433 27              ??         27h    '
    ram:00000434 a0              ??         A0h
    ram:00000435 03              ??         03h
    ram:00000436 1d              ??         1Dh
    ram:00000437 aa              ??         AAh
    ram:00000438 f7              ??         F7h
    ram:00000439 8e              ??         8Eh
    ram:0000043a f8              ??         F8h
    ram:0000043b f5              ??         F5h
    ram:0000043c c6              ??         C6h
    ram:0000043d fe              ??         FEh
    ram:0000043e 28              ??         28h    (
    ram:0000043f 9a              ??         9Ah
    ram:00000440 ed              ??         EDh
    ram:00000441 a7              ??         A7h
    ram:00000442 c9              ??         C9h
    ram:00000443 7c              ??         7Ch    |
    ram:00000444 6c              ??         6Ch    l
    ram:00000445 65              ??         65h    e
    ram:00000446 ad              ??         ADh
    ram:00000447 96              ??         96h
    ram:00000448 6e              ??         6Eh    n
    ram:00000449 ff              ??         FFh
    ram:0000044a bf              ??         BFh
    ram:0000044b ab              ??         ABh
    ram:0000044c 2b              ??         2Bh    +
    ram:0000044d 82              ??         82h
    ram:0000044e 6b              ??         6Bh    k
    ram:0000044f 4f              ??         4Fh    O
    ram:00000450 5e              ??         5Eh    ^
    ram:00000451 9d              ??         9Dh
    ram:00000452 79              ??         79h    y
    ram:00000453 99              ??         99h
    ram:00000454 42              ??         42h    B
    ram:00000455 cc              ??         CCh
    ram:00000456 5f              ??         5Fh    _
    ram:00000457 c0              ??         C0h
    ram:00000458 5d              ??         5Dh    ]
    ram:00000459 48              ??         48h    H
    ram:0000045a da              ??         DAh
    ram:0000045b b8              ??         B8h
    ram:0000045c b1              ??         B1h
    ram:0000045d 7d              ??         7Dh    }
    ram:0000045e e8              ??         E8h
    ram:0000045f 2f              ??         2Fh    /
    ram:00000460 53              ??         53h    S
    ram:00000461 d9              ??         D9h
    ram:00000462 76              ??         76h    v
    ram:00000463 40              ??         40h    @                                         ?  ->  ram:00344140
    ram:00000464 41              ??         41h    A
    ram:00000465 34              ??         34h    4
    ram:00000466 00              ??         00h
    ram:00000467 fa              ??         FAh
    ram:00000468 08              ??         08h
    ram:00000469 61              ??         61h    a
    ram:0000046a 8c              ??         8Ch
    ram:0000046b e9              ??         E9h
    ram:0000046c 73              ??         73h    s
    ram:0000046d b9              ??         B9h
    ram:0000046e 75              ??         75h    u
    ram:0000046f de              ??         DEh
    ram:00000470 09              ??         09h
    ram:00000471 8b              ??         8Bh
    ram:00000472 5a              ??         5Ah    Z
    ram:00000473 b7              ??         B7h
    ram:00000474 7a              ??         7Ah    z
    ram:00000475 a6              ??         A6h
    ram:00000476 eb              ??         EBh
    ram:00000477 01              ??         01h
    ram:00000478 30              ??         30h    0
    ram:00000479 91              ??         91h
    ram:0000047a e4              ??         E4h
    ram:0000047b 63              ??         63h    c
    ram:0000047c 10              ??         10h
    ram:0000047d 16              ??         16h
    ram:0000047e 02              ??         02h
    ram:0000047f 95              ??         95h
    ram:00000480 8a              ??         8Ah
    ram:00000481 b5              ??         B5h
    ram:00000482 f0              ??         F0h
    ram:00000483 a1              ??         A1h
    ram:00000484 19              ??         19h
    ram:00000485 17              ??         17h
    ram:00000486 69              ??         69h    i
    ram:00000487 df              ??         DFh
    ram:00000488 1f              ??         1Fh
    ram:00000489 a3              ??         A3h
    ram:0000048a 58              ??         58h    X
    ram:0000048b 25              ??         25h    %
    ram:0000048c 0a              ??         0Ah
    ram:0000048d 66              ??         66h    f
    ram:0000048e c5              ??         C5h
    ram:0000048f f2              ??         F2h
    ram:00000490 0b              ??         0Bh
    ram:00000491 f9              ??         F9h
    ram:00000492 1a              ??         1Ah
    ram:00000493 d5              ??         D5h
    ram:00000494 c8              ??         C8h
    ram:00000495 c7              ??         C7h
    ram:00000496 62              ??         62h    b
    ram:00000497 af              ??         AFh
    ram:00000498 e6              ??         E6h
    ram:00000499 ec              ??         ECh
    ram:0000049a 80              ??         80h
    ram:0000049b 7b              ??         7Bh    {
    ram:0000049c 4a              ??         4Ah    J
    ram:0000049d a5              ??         A5h
    ram:0000049e a9              ??         A9h
    ram:0000049f 88              ??         88h
    ram:000004a0 97              ??         97h
    ram:000004a1 56              ??         56h    V
    ram:000004a2 49              ??         49h    I
    ram:000004a3 b6              ??         B6h
    ram:000004a4 05              ??         05h
    ram:000004a5 cd              ??         CDh
    ram:000004a6 1e              ??         1Eh
    ram:000004a7 4d              ??         4Dh    M
    ram:000004a8 9e              ??         9Eh
    ram:000004a9 fd              ??         FDh
    ram:000004aa 24              ??         24h    $
    ram:000004ab 67              ??         67h    g
    ram:000004ac 3e              ??         3Eh    >
    ram:000004ad 07              ??         07h
    ram:000004ae 43              ??         43h    C
    ram:000004af 29              ??         29h    )
    ram:000004b0 3a              ??         3Ah    :
    ram:000004b1 db              ??         DBh
    ram:000004b2 15              ??         15h
    ram:000004b3 86              ??         86h
    ram:000004b4 78              ??         78h    x
    ram:000004b5 70              ??         70h    p
    ram:000004b6 ca              ??         CAh
    ram:000004b7 d2              ??         D2h
    ram:000004b8 1c              ??         1Ch
    ram:000004b9 b4              ??         B4h
    ram:000004ba e2              ??         E2h
    ram:000004bb 4e              ??         4Eh    N
    ram:000004bc 84              ??         84h
    ram:000004bd 04              ??         04h
    ram:000004be 51              ??         51h    Q
    ram:000004bf 81              ??         81h
    ram:000004c0 ba              ??         BAh
    ram:000004c1 68              ??         68h    h
    ram:000004c2 60              ??         60h    `
    ram:000004c3 50              ??         50h    P
    ram:000004c4 13              ??         13h
    ram:000004c5 5c              ??         5Ch    \
    ram:000004c6 7e              ??         7Eh    ~
    ram:000004c7 06              ??         06h
    ram:000004c8 98              ??         98h
    ram:000004c9 89              ??         89h
    ram:000004ca f6              ??         F6h
    ram:000004cb 38              ??         38h    8
    ram:000004cc cb              ??         CBh
    ram:000004cd cf              ??         CFh
    ram:000004ce be              ??         BEh
    ram:000004cf 23              ??         23h    #
    ram:000004d0 bd              ??         BDh
    ram:000004d1 92              ??         92h
    ram:000004d2 6d              ??         6Dh    m
    ram:000004d3 37              ??         37h    7
    ram:000004d4 d7              ??         D7h
    ram:000004d5 8f              ??         8Fh
    ram:000004d6 14              ??         14h
    ram:000004d7 f3              ??         F3h
    ram:000004d8 36              ??         36h    6
    ram:000004d9 0c              ??         0Ch
    ram:000004da ae              ??         AEh
    ram:000004db b0              ??         B0h
    ram:000004dc 3f              ??         3Fh    ?
    ram:000004dd 20              ??         20h
    ram:000004de f4              ??         F4h
    ram:000004df 52              ??         52h    R
    ram:000004e0 e0              ??         E0h
    ram:000004e1 22              ??         22h    "
    ram:000004e2 7f              ??         7Fh
    ram:000004e3 74              ??         74h    t
    ram:000004e4 46              ??         46h    F
    ram:000004e5 fc              ??         FCh
    ram:000004e6 ee              ??         EEh
    ram:000004e7 9c              ??         9Ch
    ram:000004e8 b2              ??         B2h
    ram:000004e9 87              ??         87h
    ram:000004ea 2e              ??         2Eh    .
    ram:000004eb 45              ??         45h    E
    ram:000004ec 11              ??         11h
    ram:000004ed e7              ??         E7h
    ram:000004ee d1              ??         D1h
    ram:000004ef d0              ??         D0h
    ram:000004f0 2a              ??         2Ah    *
    ram:000004f1 64              ??         64h    d
    ram:000004f2 ef              ??         EFh
    ram:000004f3 3c              ??         3Ch    <
    ram:000004f4 12              ??         12h
    ram:000004f5 59              ??         59h    Y
    ram:000004f6 ac              ??         ACh
    ram:000004f7 54              ??         54h    T
    ram:000004f8 3b              ??         3Bh    ;
    ram:000004f9 6f              ??         6Fh    o
    ram:000004fa 0d              ??         0Dh
    ram:000004fb e3              ??         E3h
    ram:000004fc dc              ??         DCh
    ram:000004fd 9b              ??         9Bh
    ram:000004fe 47              ??         47h    G
    ram:000004ff c4              ??         C4h
    ram:00000500 bb              ??         BBh
    ram:00000501 a2              ??         A2h
    ram:00000502 c2              ??         C2h
    ram:00000503 4b              ??         4Bh    K
    ram:00000504 33              ??         33h    3
    ram:00000505 83              ??         83h
    ram:00000506 d4              ??         D4h
    ram:00000507 ce              ??         CEh
    ram:00000508 c1              ??         C1h
    ram:00000509 44              ??         44h    D
    ram:0000050a dd              ??         DDh
    ram:0000050b b3              ??         B3h
    ram:0000050c 94              ??         94h
    ram:0000050d 0f              ??         0Fh
    ram:0000050e 72              ??         72h    r
    ram:0000050f 85              ??         85h
    ram:00000510 d6              ??         D6h
    ram:00000511 fb              ??         FBh
    ram:00000512 d3              ??         D3h
    ram:00000513 57              ??         57h    W
    ram:00000514 e5              ??         E5h
    ram:00000515 bc              ??         BCh
    ram:00000516 18              ??         18h
    ram:00000517 32              ??         32h    2
    ram:00000518 1b              ??         1Bh
    ram:00000519 c3              ??         C3h
    ram:0000051a 77              ??         77h    w
    ram:0000051b 55              ??         55h    U
    ram:0000051c ea              ??         EAh
    ram:0000051d 0e              ??         0Eh
    ram:0000051e e1              ??         E1h
    ram:0000051f 4c              ??         4Ch    L
    ram:00000520 96              ??         96h
    ram:00000521 3c              ??         3Ch    <
    ram:00000522 d1              ??         D1h
    ram:00000523 73              ??         73h    s
    ram:00000524 2f              ??         2Fh    /
    ram:00000525 ac              ??         ACh                                              ?  ->  ram:00c2feac
    ram:00000526 fe              ??         FEh
    ram:00000527 c2              ??         C2h
    ram:00000528 00              ??         00h
    ram:00000529 56              ??         56h    V
    ram:0000052a e1              ??         E1h
    ram:0000052b 26              ??         26h    &
    ram:0000052c 34              ??         34h    4
    ram:0000052d 9a              ??         9Ah
    ram:0000052e e1              ??         E1h
    ram:0000052f 2f              ??         2Fh    /
    ram:00000530 b5              ??         B5h
    ram:00000531 4f              ??         4Fh    O
    ram:00000532 a3              ??         A3h
    ram:00000533 86              ??         86h
    ram:00000534 fb              ??         FBh
    ram:00000535 87              ??         87h
    ram:00000536 f8              ??         F8h
    ram:00000537 91              ??         91h                                              ?  ->  ram:009b0a91
    ram:00000538 0a              ??         0Ah
    ram:00000539 9b              ??         9Bh
    ram:0000053a 00              ??         00h
    ram:0000053b fb              ??         FBh
    ram:0000053c 0f              ??         0Fh
    ram:0000053d 8d              ??         8Dh                                              ?  ->  ram:0077248d
    ram:0000053e 24              ??         24h    $                                         ?  ->  ram:00007724
    ram:0000053f 77              ??         77h    w                                         ?  ->  ram:00000077

```

Now that we know the encryption algorithm, key, and ciphertext, we can write a decryption script

```
# CTF Exploit - WASM Reverse Challenge
# Decrypt using data extracted from Ghidra

# ===== key_data extracted from 0x400 =====
key_data = [
    0x80, 0x80, 0x58, 0x4B, 0xC6, 0x16, 0x5E, 0x90,
    0x95, 0xB5, 0x36, 0xAA, 0x5E, 0x54, 0xFE, 0x9A
]

# ===== key_transform extracted from 0x410 =====
key_transform = [
    0xAB, 0xCD, 0x17, 0x39, 0x5E, 0x82, 0xF1, 0x4A,
    0x63, 0xB7, 0x2C, 0x90, 0xD5, 0x08, 0x7F, 0xE6
]

# ===== SBOX extracted from 0x420 (256 bytes) =====
SBOX = [
    0x39, 0x26, 0x2D, 0x21, 0xA8, 0x31, 0x35, 0x9F,
    0x6A, 0x5B, 0x3D, 0x71, 0xA4, 0x8D, 0xF1, 0x2C,
    0x90, 0xD8, 0x93, 0x27, 0xA0, 0x03, 0x1D, 0xAA,
    0xF7, 0x8E, 0xF8, 0xF5, 0xC6, 0xFE, 0x28, 0x9A,
    0xED, 0xA7, 0xC9, 0x7C, 0x6C, 0x65, 0xAD, 0x96,
    0x6E, 0xFF, 0xBF, 0xAB, 0x2B, 0x82, 0x6B, 0x4F,
    0x5E, 0x9D, 0x79, 0x99, 0x42, 0xCC, 0x5F, 0xC0,
    0x5D, 0x48, 0xDA, 0xB8, 0xB1, 0x7D, 0xE8, 0x2F,
    0x53, 0xD9, 0x76, 0x40, 0x41, 0x34, 0x00, 0xFA,
    0x08, 0x61, 0x8C, 0xE9, 0x73, 0xB9, 0x75, 0xDE,
    0x09, 0x8B, 0x5A, 0xB7, 0x7A, 0xA6, 0xEB, 0x01,
    0x30, 0x91, 0xE4, 0x63, 0x10, 0x16, 0x02, 0x95,
    0x8A, 0xB5, 0xF0, 0xA1, 0x19, 0x17, 0x69, 0xDF,
    0x1F, 0xA3, 0x58, 0x25, 0x0A, 0x66, 0xC5, 0xF2,
    0x0B, 0xF9, 0x1A, 0xD5, 0xC8, 0xC7, 0x62, 0xAF,
    0xE6, 0xEC, 0x80, 0x7B, 0x4A, 0xA5, 0xA9, 0x88,
    0x97, 0x56, 0x49, 0xB6, 0x05, 0xCD, 0x1E, 0x4D,
    0x9E, 0xFD, 0x24, 0x67, 0x3E, 0x07, 0x43, 0x29,
    0x3A, 0xDB, 0x15, 0x86, 0x78, 0x70, 0xCA, 0xD2,
    0x1C, 0xB4, 0xE2, 0x4E, 0x84, 0x04, 0x51, 0x81,
    0xBA, 0x68, 0x60, 0x50, 0x13, 0x5C, 0x7E, 0x06,
    0x98, 0x89, 0xF6, 0x38, 0xCB, 0xCF, 0xBE, 0x23,
    0xBD, 0x92, 0x6D, 0x37, 0xD7, 0x8F, 0x14, 0xF3,
    0x36, 0x0C, 0xAE, 0xB0, 0x3F, 0x20, 0xF4, 0x52,
    0xE0, 0x22, 0x7F, 0x74, 0x46, 0xFC, 0xEE, 0x9C,
    0xB2, 0x87, 0x2E, 0x45, 0x11, 0xE7, 0xD1, 0xD0,
    0x2A, 0x64, 0xEF, 0x3C, 0x12, 0x59, 0xAC, 0x54,
    0x3B, 0x6F, 0x0D, 0xE3, 0xDC, 0x9B, 0x47, 0xC4,
    0xBB, 0xA2, 0xC2, 0x4B, 0x33, 0x83, 0xD4, 0xCE,
    0xC1, 0x44, 0xDD, 0xB3, 0x94, 0x0F, 0x72, 0x85,
    0xD6, 0xFB, 0xD3, 0x57, 0xE5, 0xBC, 0x18, 0x32,
    0x1B, 0xC3, 0x77, 0x55, 0xEA, 0x0E, 0xE1, 0x4C
]

# ===== target ciphertext extracted from 0x520 (32 bytes) =====
target = [
    0x96, 0x3C, 0xD1, 0x73, 0x2F, 0xAC, 0xFE, 0xC2,
    0x00, 0x56, 0xE1, 0x26, 0x34, 0x9A, 0xE1, 0x2F,
    0xB5, 0x4F, 0xA3, 0x86, 0xFB, 0x87, 0xF8, 0x91,
    0x0A, 0x9B, 0x00, 0xFB, 0x0F, 0x8D, 0x24, 0x77
]

# ===== Build inverse S-Box =====
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

# ===== Key recovery algorithm reversed from unnamed_function_2 =====
# Decompiled code shows: result = (encoded ^ transform) - (idx * 0x17)
def recover_key():
    key = []
    for i in range(16):
        tmp = key_data[i] ^ key_transform[i]
        tmp = (tmp - (i * 0x17)) & 0xFF
        key.append(tmp)
    return key

# ===== AES inverse operations =====
def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]

def inv_shift_rows(state):
    s = state[:]
    # Inverse ShiftRows
    s[1], s[5], s[9], s[13] = state[13], state[1], state[5], state[9]
    s[2], s[6], s[10], s[14] = state[10], state[14], state[2], state[6]
    s[3], s[7], s[11], s[15] = state[7], state[11], state[15], state[3]
    return s

def gf_mult(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def inv_mix_single_column(col):
    a, b, c, d = col
    return [
        gf_mult(0x0e, a) ^ gf_mult(0x0b, b) ^ gf_mult(0x0d, c) ^ gf_mult(0x09, d),
        gf_mult(0x09, a) ^ gf_mult(0x0e, b) ^ gf_mult(0x0b, c) ^ gf_mult(0x0d, d),
        gf_mult(0x0d, a) ^ gf_mult(0x09, b) ^ gf_mult(0x0e, c) ^ gf_mult(0x0b, d),
        gf_mult(0x0b, a) ^ gf_mult(0x0d, b) ^ gf_mult(0x09, c) ^ gf_mult(0x0e, d),
    ]

def inv_mix_columns(state):
    result = state[:]
    for i in range(4):
        col = [state[i*4 + j] for j in range(4)]
        new_col = inv_mix_single_column(col)
        for j in range(4):
            result[i*4 + j] = new_col[j]
    return result

def add_round_key(state, rk):
    return [s ^ k for s, k in zip(state, rk)]

# ===== Key expansion (reversed from decompiled code) =====
# rkeys[r][i] = rkeys[r-1][i] ^ (r * 0x11) ^ i
def expand_key(key):
    rkeys = [list(key)]
    for r in range(1, 11):
        rk = []
        rc = (r * 0x11) & 0xFF
        for i in range(16):
            rk.append(rkeys[r-1][i] ^ rc ^ i)
        rkeys.append(rk)
    return rkeys

# ===== Decrypt single block =====
def decrypt_block(block, rkeys):
    state = list(block)

    # Inverse final AddRoundKey
    state = add_round_key(state, rkeys[10])

    # Inverse rounds 10 to 1
    for r in range(10, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, rkeys[r-1])
        if r > 1:
            state = inv_mix_columns(state)

    return state

# ===== Main =====
def main():

    # Recover key
    key = recover_key()
    print(f"[*] Recovered key: {bytes(key)}")

    # Expand key
    rkeys = expand_key(key)

    # ECB decrypt
    plaintext = []
    for i in range(0, len(target), 16):
        block = target[i:i+16]
        dec = decrypt_block(block, rkeys)
        plaintext.extend(dec)

    # Remove PKCS7 padding
    pad_len = plaintext[-1]
    if 1 <= pad_len <= 16:
        plaintext = plaintext[:-pad_len]

    flag = bytes(plaintext).decode('utf-8', errors='ignore')
    print(f"[+] FLAG: {flag}")

if __name__ == "__main__":
    main()

```



