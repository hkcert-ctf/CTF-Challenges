* Challenge Name: findkey

* Writeup:

  This challenge primarily tests two core technical points: AES white-box cryptography attacks and control flow flattening deobfuscation. The challenge implements AES encryption in white-box form and obfuscates the code through control flow flattening. You need to first understand and remove the obfuscation layer, then perform side-channel analysis on the white-box AES implementation, and finally recover the complete AES key.

  Solution reference: https://blog.csdn.net/fenfei331/article/details/126385120
  You need to first obtain the AES 10th round key:

```python
import phoenixAES

with open('tracefile', 'wb') as t:
    t.write("""
d452dc4d2c848077d6187d4ebaca0d71
1f52dc4d2c848091d6185b4ebac30d71
5652dc4d2c8480d8d618724eba610d71
3452dc4d2c84805cd618434eba650d71
c952dc4d2c848028d618614eba500d71
d40bdc4d9b848077d6187d34baca4771
d441dc4d94848077d6187ddabaca6271
d436dc4d06848077d6187de1bacaac71
d4c2dc4de7848077d6187deabaca6071
d4526f4d2c37807700187d4ebaca0d80
d452094d2c3a807740187d4ebaca0d7b
d452624d2c93807754187d4ebaca0d36
d452f04d2c54807710187d4ebaca0d17
d452dc1f2c84c877d64b7d4e17ca0d71
d452dc752c847677d6257d4ecfca0d71
d452dc2b2c842277d6087d4e16ca0d71
d452dc3e2c843377d6817d4e2dca0d71
""".encode('utf8'))
phoenixAES.crack_file('tracefile', [], True, False, 3)
```

The core algorithm of the phoenixAES tool analyzes the differential characteristics of these samples and uses statistical analysis to identify correlations with the key. Since the last few rounds of AES have the most direct relationship with the key, the attack starts from the 10th round (the last round) and works backwards to derive the first round key.
