The question first randomly generated key2, which is fixed in subsequent encryption. Then we were given up to 9 opportunities to select plaintext, but the input plaintext would be hashed with sha256, and each time we selected plaintext, key1 and key3 would be regenerated. Key1 was not directly leaked, but the last line of key-expand was leaked. By analyzing key-expand, we can see that this is actually finding the 16th power of the friendly matrix of key1, which is $x ^ {31} $minus the polynomial with leaf as the coefficient. By factoring this polynomial, several factors can be obtained. By using depth first search to find the first polynomial factor with the highest degree of 16, there is a probability of recovering key1. There may be multiple solutions, or the decomposition may fail.

```python
from pwn import *
import hashlib

rem = remote('127.0.0.1', 63553)
data = []

for _ in range(9):
    d = {}
    rem.sendline(b'1')
    rem.recvuntil(b'choice: ')
    rem.send(str(_).encode())
    d['msg'] = hashlib.sha256(str(_).encode().ljust(32,b'\x00')).hexdigest()
    rem.recvuntil(b'leak: ')
    k1 = rem.recvuntil(b'\n')[:-1]
    F.<x> = Zmod(256)[]
    k1 = bytes.fromhex(k1.decode())
    f1 = x^31-sum([j*x^i for i,j in enumerate(k1)])
    try:
        s = list(factor(f1))
    except:
        print('cannot factor')
        continue
    import itertools
    ls = set()
    def search(res,choices):
        if res.degree() == 16:
            ls.add(res)
            return
        elif res.degree() > 16:
            return
        for i,j in enumerate(s):
            if i in choices:
                continue
            search(res*j[0],choices+[i])
    search(F(1),[])
    ls = [bytes([(x^16-i).monomial_coefficient(x^j) for j in range(16)]).hex() for i in ls]
    print(sorted(ls))
```
输出结果（示例）：
```python
cannot factor
['02090d060505090f050303090a030101', '228f98d59749f113859c4d8e476e3839', '5f11e9d0f81e0c2a77df615b5d201112']
['06080c070e00030d0e07060d0009000a', 'e6a0c2d320419f723e22fb9df863affb']
['010e0505000304010e020306060e0203', 'cd6d2e2809898e71e64e9b2c7068de41']
['00050e0f0b070c010b0e0a030d030308', '00d8bd97e710bc337dd964037acdbdf8', '5895163753a784299bbe721b756bc390', '89eba9d6fe83c1c8f12029342c22ab53']
['0d0506040a01080a03040e030c0e0c05', '71289119d37777f015f557a4b4536fff', 'c3437f7e2b9e5e514434a6b7d998bf5a']
cannot factor
['090e0b0e0400060904010d030105060e']
cannot factor
```

注意到 twist 函数有后门，输出结果一定满足所有字节高位为 0，通过分析上述输出结果，注意到每一组有解的 key1 中都必定存在一个 key1 满足每个字节的高位都为 0，可以判断出这个 key1 是正确的。

分析加密函数，实际上这是在做多项式 msg 和多项式 key2 在 Zmod(256) 上乘法，再模上一个多项式 key1，再与 key3 异或。根据上述分析，key3 经过 twist 后是一个小量，可以把异或 key3 看成加上一个小的误差，这个加密算法就可以看成 RLWE 问题，构造格用 LLL 或 BKZ 攻击，格的构造方法见代码注释（AI 生成）。一般只要 4 组密文就能恢复 key2 ，这里由于 key1 可能恢复失败，我们选择 9 次明文以增加成功的组数。

```python
from pwn import *
import hashlib
import binascii

BLOCK_SIZE = 16

def get_key_expand(key1):
    # 重写密钥扩展逻辑
    key_expand = [[0] * BLOCK_SIZE for _ in range(BLOCK_SIZE)]
    for i in range(BLOCK_SIZE):
        key_expand[0][i] = key1[i]
    for i in range(BLOCK_SIZE - 1):
        key_expand[i+1][0] = (key_expand[i][BLOCK_SIZE-1] * key1[0]) % 256
        for j in range(BLOCK_SIZE - 1):
            term = (key_expand[i][BLOCK_SIZE-1] * key1[j+1]) % 256
            key_expand[i+1][j+1] = (key_expand[i][j] + term) % 256
    return key_expand

def simulate_enc_only(msg_block, key2, key_expand):
    # 模拟加密过程中的中间变量 enc 计算
    # 所有的运算都在 mod 256 下进行
    enc = [0] * BLOCK_SIZE
    for i in range(BLOCK_SIZE):
        enc[i] = (msg_block[i] * key2[0]) % 256
    for i in range(1, BLOCK_SIZE):
        # Part 1
        for j in range(BLOCK_SIZE - i):
            term = (key2[i] * msg_block[j]) % 256
            enc[i+j] = (enc[i+j] + term) % 256
        # Part 2
        for j in range(BLOCK_SIZE - i, BLOCK_SIZE):
            for k in range(BLOCK_SIZE):
                # enc[k] += key2[i] * msg[j] * key_expand[...]
                factor = (key2[i] * msg_block[j]) % 256
                term = (factor * key_expand[i+j-BLOCK_SIZE][k]) % 256
                enc[k] = (enc[k] + term) % 256
    return enc

def build_matrix_A(msg, key1):
    # 构建线性矩阵 A
    # A * key2 = enc (mod 256)
    # 我们通过传入基向量 (unit vectors) 来提取矩阵的列
    key_expand = get_key_expand(key1)
    num_blocks = len(msg) // BLOCK_SIZE
    
    # 矩阵大小: (128 rows, 16 columns)
    # 我们用列表的列表来表示，稍后转为 Sage 矩阵
    matrix_cols = []
    
    for k in range(BLOCK_SIZE):
        # 构造一个 key2，只有第 k 位是 1，其他是 0
        probe_key2 = [0] * BLOCK_SIZE
        probe_key2[k] = 1
        
        col_k = []
        for b in range(num_blocks):
            block_msg = msg[b*BLOCK_SIZE : (b+1)*BLOCK_SIZE]
            block_enc = simulate_enc_only(block_msg, probe_key2, key_expand)
            col_k.extend(block_enc)
        matrix_cols.append(col_k)
        
    # 转置：matrix_cols 存储的是列，我们需要行优先的矩阵
    # 或者直接用 Matrix 从列构造
    A = Matrix(Zmod(256), matrix_cols)
    return A

def solve_round(data):
    print("[*] Building Lattice Matrix...")
    
    # 1. 构建线性变换矩阵 A
    As = []
    b_approxes = []
    for i in data:
        msg = [x for x in binascii.unhexlify(i['msg'])]
        key1 = [x for x in binascii.unhexlify(i['key1'])]
        ciphertext = [x for x in binascii.unhexlify(i['enc'])]
        A = build_matrix_A(msg, key1)
        As.append(A)
        
        # 2. 构建目标向量 b (enc 的近似值)
        # 我们知道 ciphertext & 0x0F == enc >> 4
        # 所以 enc 大约是 (ciphertext & 0x0F) * 16 + 8 (取区间中心)
        b_approx = []
        for c in ciphertext:
            b_approx.append(c)
        b_approxes.extend(b_approx)
    A = block_matrix([As])
    
    nrows, ncols = A.dimensions() # 16, 128
    print(A.dimensions())
    
    # 3. 构造 CVP/LWE 格
    # 我们要寻找 k2 使得 A * k2 ≈ b (mod 256)
    # 等价于寻找 Lattice 中的向量 v = A*k2 + 256*z，使得 v 接近 b
    # 构造嵌入式格 (Embedding Lattice)
    # Basis Matrix B (row-based for LLL):
    # [   1  ,  0, ..., 0,  row_0(A^T) ]  <- 代表 k2 的分量 (weight=0, 不限制 k2 大小) -> 这里其实不需要
    # ...
    # [   0  ,  0, ..., 0,  256*I      ]  <- 模数规约
    # [   0  ,  0, ..., K,  -b         ]  <- 目标向量
    
    # 简化的 Lattice 构造：只关注残差 (Residuals)
    # 我们要找 e = A*k2 - b (mod 256) 使得 e 很小
    # Lattice L 由 A 的列向量和 256*I 生成
    # 我们构造矩阵 M，行向量由 (A的列) 和 (256*I的列) 组成
    # 并在最后添加一行 (-b, K)
    
    dim_lattice = ncols + 1
    # 行数: 16 (来自A) + 128 (来自256I) + 1 (目标)
    M = Matrix(ZZ, 16 + ncols + 1, dim_lattice)
    
    # 填充 A 的转置 (作为行向量放入 M)
    # 注意 A 的元素是在 Zmod(256)，需要 lift 到 ZZ
    A_lift = A.change_ring(ZZ)
    for i in range(16):
        # 第 i 列 A -> M 的第 i 行
        # 前 128 列是 A 的列向量，最后一列是 0
        for r in range(ncols):
            M[i, r] = A_lift[i, r]
    
    # 填充 256*I
    for i in range(ncols):
        M[16 + i, i] = 256
        
    # 填充目标向量 -b
    K = 64 # 权重因子，用于锁定目标行
    for i in range(ncols):
        M[16 + ncols, i] = -b_approxes[i]
    M[16 + ncols, ncols] = K
    
    print("[*] Running LLL reduction (this might take a second)...")
    M_reduced = M.BKZ()
    
    # 4. 寻找包含 K 的短向量
    # 我们期望找到一行: (e_0, e_1, ..., e_127, K) 或 (..., -K)
    # 其中 e 是误差向量
    error_vector = None
    
    for row in M_reduced:
        if row[ncols] == K:
            error_vector = row[:ncols]
            break
        elif row[ncols] == -K:
            error_vector = [-x for x in row[:ncols]]
            break
            
    if error_vector is None:
        print("[-] Failed to find vector with correct last coordinate.")
        return None

    print(f"[+] Found error vector. Norm: {float(error_vector.norm())}")
    
    # 5. 恢复准确的 enc = b_approx + error
    enc_recovered = vector(Zmod(256), ncols)
    for i in range(ncols):
        enc_recovered[i] = b_approxes[i] + error_vector[i]
        
    # 6. 解线性方程组 A * k2 = enc_recovered
    # 这是一个超定方程组 (128 equations, 16 vars)
    # 直接使用 Sage 的 solve_right
    try:
        k2_sol = A.solve_left(enc_recovered)
        return bytearray(k2_sol)
    except ValueError as e:
        print(e)
        print("[-] Linear system has no solution. Lattice reduction might have failed.")
        return None

def main():
    rem = remote('127.0.0.1', 63553)
    data = []
    
    for _ in range(9):
        d = {}
        rem.sendline(b'1')
        rem.recvuntil(b'choice: ')
        rem.send(str(_).encode())
        d['msg'] = hashlib.sha256(str(_).encode().ljust(32,b'\x00')).hexdigest()
        rem.recvuntil(b'leak:')
        k1 = rem.recvuntil(b'\n')[1:-1]
        F.<x> = Zmod(256)[]
        k1 = bytes.fromhex(k1.decode())
        f1 = x^31-sum([j*x^i for i,j in enumerate(k1)])
        try:
            s = list(factor(f1))
        except:
            continue
        import itertools
        ls = set()
        def search(res,choices):
            if res.degree() == 16:
                ls.add(res)
                return
            elif res.degree() > 16:
                return
            for i,j in enumerate(s):
                if i in choices:
                    continue
                search(res*j[0],choices+[i])
        search(F(1),[])
        ls = [bytes([(x^16-i).monomial_coefficient(x^j) for j in range(16)]) for i in ls]
        ls = [i.hex() for i in ls if all([j<16 for j in i])]
        if len(ls) == 0:
            continue
        d['key1'] = ls[0]
        rem.recvuntil(b'enc: ')
        d['enc'] = rem.recvuntil(b'\n')[:-1]
        data.append(d)
    print(data)
    res = solve_round(data)
    if not res:
        print("Failed.")
    print(f"key2: {res.hex()}")
    rem.sendline(b'2')
    rem.recv()
    rem.send(res)
    print(rem.recv())
    try:
        print(rem.recvuntil(b'}'))
    except EOFError:
        pass
    rem.close()

if __name__ == "__main__":
    main()
```