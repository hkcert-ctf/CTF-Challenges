First, p is a small prime number and can be brute-forced

$t_{1}=k*(m+r_{1})^{-1}\pmod p$

$t_{2}=k*(m+r_{2})^{-1}\pmod p$

$m=k*t_{1}^{-1}-r_{1}\pmod p$

$m=k*t_{2}^{-1}-r_{2}\pmod p$

$k*(t_{1}^{-1}-t_{2}^{-1})-(r_{1}-r_{2})\equiv 0\pmod p$

$t_{1}=leak_{1}<<244+b_{1}=A_{1}+b_{1}$

$t_{2}=leak_{2}<<244+b_{2}=A_{2}+b_{2}$

$t_{1}^{-1}-t_{2}^{-1}=\frac{t_{2}-t_{1}}{t_{1}*t_{2}}$

$k*(A_{2}-A_{1}+b_{2}-b_{1})-(r_{1}-r_{2})*(A_{1}+b_{1})*(A_{2}+b_{2})\equiv 0\pmod p$

$f(x,y)=k*(A_{2}-A_{1}+y-x)-(r_{1}-r_{2})*(A_{1}+x)*(A_{2}+y)\equiv 0\pmod p$

Here's the `small_roots` function (such a great thing), and searching for "binary copper" should yield quite a few blog posts

```py
# sage
from sage.all import *
from Crypto.Util.number import *
import itertools

def small_roots(f, bounds, m=1, d=None):
    if not d:
        d = f.degree()

    R = f.base_ring()
    N = R.cardinality()

    f /= f.coefficients().pop(0)
    f = f.change_ring(ZZ)

    G = Sequence([], f.parent())
    for i in range(m + 1):
        base = N ^ (m - i) * f ^ i
        for shifts in itertools.product(range(d), repeat=f.nvariables()):
            g = base * prod(map(power, f.variables(), shifts))
            G.append(g)

    B, monomials = G.coefficient_matrix()
    monomials = vector(monomials)

    factors = [monomial(*bounds) for monomial in monomials]
    for i, factor in enumerate(factors):
        B.rescale_col(i, factor)

    B = B.dense_matrix().LLL()

    B = B.change_ring(QQ)
    for i, factor in enumerate(factors):
        B.rescale_col(i, 1 / factor)

    H = Sequence([], f.parent().change_ring(QQ))
    for h in filter(None, B * monomials):
        H.append(h)
        I = H.ideal()
        if I.dimension() == -1:
            H.pop()
        elif I.dimension() == 0:
            roots = []
            for root in I.variety(ring=ZZ):
                root = tuple(R(root[var]) for var in f.variables())
                roots.append(root)
            return roots

    return []

e = 65537
N = 3333577291839009732612693330613476891341287017491683764014849337158389717338712200133085615150269196268856288361865352673921704626130772582853528604556994221890454520933132803888321775335519781063447756692130742361931522856942232406992357982482263472763363458621836220024977864980600979194500121897419553619426163227
c = 1277272201928931051067525742142583320131498687502905469530557519241347169899260720694873154669476372724906606385788056536109971768256973988460766527896895880291037980646963981472637862512247195798266373251524526460097881602691641026093728861572872156172787168597410496150253340538386296663073088345799201197096884740
k = 9352039867057736323
r1 = 10421792656200324147964684790160875926436411483496860422433732508593789212449544620816674407170998779863336939494663076247759140488927744939619406024905901
r2 = 8806088830734144089522276896226392806947836111998696180055727048752624989402057411311728398322297424598954586424896296000606209022432442660527640463521679
leak1 = 4266222222502644630611545246271868348722888987303187402827005454059765428769160822475080050046035916876078546634293907218937483241284454918367519709206766322037148585465519188582916280829212776096606923824120883699251868362915920299645
leak2 = 1176921186497191878459783787148403806360469809421921990427675048480656171919274113895695842508460760829511824635106692634456334400022597605585661597793889066395539405395254174368285751236344600489419240628821864912762242188289636510706

for i in range(2**24, 2**25):
    if N % i == 0:
        q = i
        p = N // i
        break
print(long_to_bytes(pow(c, inverse(e, (p-1)*(q-1)), N)).decode())

PR.<x,y> = PolynomialRing(Zmod(p))
A1 = leak1 << 244
A2 = leak2 << 244
f = k * (A2 - A1 + y - x) - (r1 - r2) * (A1 + x) * (A2 + y)
res = small_roots(f, (2^244, 2^244), m = 1, d = 3)
for root in res:
    b1,b2 = root
    m = k*inverse(A1+b1, p) - r1
    print(long_to_bytes(int(m)).decode())
    break
```
