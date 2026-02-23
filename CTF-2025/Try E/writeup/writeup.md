When e is very large in RSA encryption, d will be very small, and when $d<\ frac {1} {3}N ^When {\ frac {1} {4}} $, we often use * * Wiener Attack * * to solve for d. The general principle is:
The conventional Wiener Attack is usually expanded using $\ frac eN $for continuous fractions. However, for this question, since $e and N $are both very close in 2048 bits, $\ frac Ne $can also be used
Lemma: If there exists an integer $a, b $such that $| x - \ frac {a} {b} |<\ frac {1} {2b ^ 2} $(or similar common bounds), then $\ frac {a} {b} $must be some convergence fraction in the $x $continued fraction expansion

In RSA encryption, there is $ed \ equiv 1 \ mod (\ phi (N)) $, which is $ed=k \ phi (N)+1 $. Since n is 2048 bits, which is very large, there is $\ phi (N) \ approximate N$
So there are:
$$ed=kN+1$$
Write in fraction expansion form: $\ frac {N} {e}- \frac{d}{k}=-\frac{1}{ek}$
Since $e>>k $, it can be inferred that $\ frac {1} {ek}<<\ frac {1} {2k ^ 2} $clearly satisfies the lemma condition, that is, $\ frac dk $will appear in the convergence value of the continued fraction expansion of $\ frac Ne $

Specific mathematical principles and Python code can be found in this blog post:
https://hasegawaazusa.github.io/wiener-attack.html

```py
from Crypto.Util.number import *


def continuedFra(x, y):
    cf = []
    while y:
        cf.append(x // y)
        x, y = y, x % y
    return cf


def gradualFra(cf):
    numerator = 0
    denominator = 1
    for x in cf[::-1]:
        numerator, denominator = denominator, x * denominator + numerator
    return numerator, denominator


def getGradualFra(cf):
    gf = []
    for i in range(1, len(cf) + 1):
        gf.append(gradualFra(cf[:i]))
    return gf


def wienerAttack(e, n):
    cf = continuedFra(e, n)
    gf = getGradualFra(cf)
    for d, k in gf:
        if d.bit_length() == 256:
            return d


N = 
e = 
c = 
d = wienerAttack(e, N)
flag = long_to_bytes(pow(c, d, N)).decode()
print(flag)
```
