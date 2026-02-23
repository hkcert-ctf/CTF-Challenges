# Writeup

After decompiling `sm4chal.jar` using JADX, two classes were discovered:

### 2.  Main class analysis

```java
public class Main {
    private static final String KEY_SEED = "happ";
    private static final byte[] KEY = Sm4.deriveKeyFromSeed(KEY_SEED);
    private static final String TARGET_CIPHER_HEX = "21c2692a4775c413356a31fc55c38f6218bed9d46c45bd0eb777be9334c999d7";

    public static void main(String[] strArr) throws Exception {
        if (Sm4.toHex(Sm4.encrypt(KEY, line.getBytes(StandardCharsets.UTF_8))).equals(TARGET_CIPHER_HEX)) {
            System.out.println("Correct");
        }
    }
}
```

- Key seed: `"happ"`
- Target ciphertext: `21c2692a4775c413356a31fc55c38f6218bed9d46c45bd0eb777be9334c999d7`
- Verification logic: `encrypt(flag) == target_cipher`

### 3.  Sm4 category analysis

#### 3.1 Key derivation

```java
public static byte[] deriveKeyFromSeed(String str) {
    byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
    byte[] bArr = new byte[16];
    for (int i = 0; i < 16; i++) {
        bArr[i] = (byte) (((bytes[i % bytes.length] & 255) + (i * 17) + 35) & 255);
    }
    return bArr;
}
```

Derive a 16-byte key from the seed "happ".

#### 3.2 Modified S-Box

This is the key modification point of the problem. The standard SM4 uses fixed S-Boxes, but this problem uses the derived `SBOX_P`:

```java
static {
    for (int i = 0; i < 256; i++) {
        SBOX_P[i] = (byte) rotl8(SBOX[(i ^ 167) & 255] & 255, i & 3);
    }
}

private static int sboxTransform(int i) {
    return SBOX_P[(i ^ 60) & 255] & 255;
}
```

1. XOR the original index `i` with `167` first
2. Perform a lookup table lookup before performing a left shift by `(i & 3)` bits
3. When using, XOR the index with `60`

### 4.  Decryption approach

SM4 is a symmetric block cipher, and the decryption process is the same as the encryption process, only requiring the 32 round keys to be used in reverse order.

##  exp

```python
#!/usr/bin/env python3
# SM4 Decryption for sm4chal.jar

SBOX = bytes([
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
])

FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
]


def rotl8(val, shift):
    shift &= 7
    return ((val << shift) | (val >> (8 - shift))) & 0xff


def build_sbox_p():
    sbox_p = bytearray(256)
    for i in range(256):
        sbox_p[i] = rotl8(SBOX[(i ^ 167) & 255], i & 3)
    return bytes(sbox_p)


SBOX_P = build_sbox_p()


def sbox_transform(val):
    return SBOX_P[(val ^ 60) & 255]


def rotl32(val, shift):
    val &= 0xffffffff
    return ((val << shift) | (val >> (32 - shift))) & 0xffffffff


def tau(val):
    b0 = sbox_transform((val >> 24) & 0xff)
    b1 = sbox_transform((val >> 16) & 0xff)
    b2 = sbox_transform((val >> 8) & 0xff)
    b3 = sbox_transform(val & 0xff)
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3


def T(val):
    t = tau(val)
    return t ^ rotl32(t, 2) ^ rotl32(t, 10) ^ rotl32(t, 18) ^ rotl32(t, 24)


def T_prime(val):
    t = tau(val)
    return t ^ rotl32(t, 13) ^ rotl32(t, 23)


def bytes_to_int(data, offset):
    return ((data[offset] & 0xff) << 24) | ((data[offset+1] & 0xff) << 16) | \
           ((data[offset+2] & 0xff) << 8) | (data[offset+3] & 0xff)


def int_to_bytes(val):
    return bytes([(val >> 24) & 0xff, (val >> 16) & 0xff, (val >> 8) & 0xff, val & 0xff])


def derive_key(seed):
    seed_bytes = seed.encode('utf-8')
    key = bytearray(16)
    for i in range(16):
        key[i] = ((seed_bytes[i % len(seed_bytes)] & 0xff) + (i * 17) + 35) & 0xff
    return bytes(key)


def expand_key(key):
    k = [bytes_to_int(key, i*4) for i in range(4)]
    mk = [(k[i] ^ FK[i]) & 0xffffffff for i in range(4)]
    rk = []
    state = mk[:]
    for i in range(32):
        tmp = (state[1] ^ state[2] ^ state[3] ^ CK[i]) & 0xffffffff
        new_val = (state[0] ^ T_prime(tmp)) & 0xffffffff
        rk.append(new_val)
        state = state[1:] + [new_val]
    return rk


def decrypt_block(block, rk):
    x = [bytes_to_int(block, i*4) for i in range(4)]
    # 解密: 轮密钥反序使用
    for i in range(32):
        tmp = (x[1] ^ x[2] ^ x[3] ^ rk[31-i]) & 0xffffffff
        new_val = (x[0] ^ T(tmp)) & 0xffffffff
        x = x[1:] + [new_val]
    return int_to_bytes(x[3]) + int_to_bytes(x[2]) + int_to_bytes(x[1]) + int_to_bytes(x[0])


def decrypt(key, ciphertext):
    rk = expand_key(key)
    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        plaintext += decrypt_block(ciphertext[i:i+16], rk)
    return plaintext


def pkcs7_unpad(data):
    return data[:-data[-1]]


# 解密
target_hex = "21c2692a4775c413356a31fc55c38f6218bed9d46c45bd0eb777be9334c999d7"
ciphertext = bytes.fromhex(target_hex)
key = derive_key("happ")
plaintext = pkcs7_unpad(decrypt(key, ciphertext))
print(plaintext.decode('utf-8'))
```

## Execution result

```
Key: 8b95b5c6cfd9f90a131d3d4e57618192
Decrypted (padded): 666c61677b486176655f415f4e6963655f4461797979797d0808080808080808
Decrypted: 666c61677b486176655f415f4e6963655f4461797979797d

=== FLAG ===
flag{Have_A_Nice_Dayyyy}
```

## Flag

```
flag{Have_A_Nice_Dayyyy}
```

