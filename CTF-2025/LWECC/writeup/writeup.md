## LWECC

### Design concept

Vulnerability point:

+The curve order is equal to p, and Smart's attack can be used to solve ECDLP
+The LWE problem of binary unknown errors is essentially equivalent to the LWE of binary errors, and can be solved using LLL on a small scale

### Solution steps

Firstly, it is observed that the order of the curve is equal to the modulus p. Therefore, Smart's attack solution list b can be used to generate ECDLP for the curve element G. At this point, it is equivalent to recovering a binary unknown error LWE problem:
$$
b = As + e \quad , \quad e_i \in \{E_1, E_2\}
$$
And as long as $\ {E1, E2 \} $is mapped to 01 using affine transformation, the short vector e can be reduced, and then the private key s can be recovered by solving the matrix equation.



```
A = 
b = 
enc = 

from Crypto.Util.number import *
from Crypto.Cipher import AES
from random import choice
from hashlib import md5

def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

p = 1096126227998177188652856107362412783873814431647
E = EllipticCurve(GF(p), [0, 5])
G = E.gens()[0]

s = [E.random_element() for _ in range(73)]
e = [E.random_element() for _ in "01"]
A = Matrix(GF(p), 137, 73, A)
b_ = [SmartAttack(G, E(i), p) for i in b]

from subprocess import check_output

def flatter(M):
    # compile https://github.com/keeganryan/flatter and put it in $PATH
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    from re import findall
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

def primal_attack_binary_error(A,b,m,p):
    M = block_matrix(Zmod(p), [
        [A.T],
        [matrix(ZZ, b)],
        [matrix(ZZ, [1]*m)]
    ])

    M1, M2 = M[:, :M.nrows()], M[:, M.nrows():]
    
    L = block_matrix(ZZ, [
        [1, M1^(-1)*M2],
        [0, p]
    ])
    X = flatter(L)
    Y = Matrix(ZZ, X) * Matrix(ZZ, L)^(-1) # X = Y*L
    Y = Matrix(ZZ, Y)

    k, t = (Y[:M.nrows(), :M.nrows()] * M1^(-1))[0][-2:]
    e = (X[0] - vector(Zmod(p), [t]*m)) * inverse(k, p)
    
    return e

e2 = primal_attack_binary_error(A, b_, 137, p)
s_ = A.solve_right(vector(GF(p), b_) - e2)
s = [_*G for _ in s_]
flag = AES.new(key=md5(str(s).encode()).digest(), nonce=b"LWECC", mode=AES.MODE_CTR).decrypt(enc)
print(flag)
```

