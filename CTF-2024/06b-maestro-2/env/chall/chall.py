import random
import os
from Crypto.Cipher import AES as _AES

from aes import AES


def test():
    key = os.urandom(32)
    m = os.urandom(16)
    seed = os.urandom(16)

    cipher = _AES.new(key, _AES.MODE_ECB)
    c0 = cipher.encrypt(m)

    cipher = AES(key)
    c1 = cipher.encrypt_block(m)
    assert c0 == c1

    cipher = AES(key, seed=seed)
    c2 = cipher.encrypt_block(m)
    assert c0 != c2


def main():
    # Do not submit hkcert24{***REDACTED***}. The actual flag is in the netcat service!
    flag = os.environ.get('FLAG', 'hkcert24{***REDACTED***}')

    seed = bytes.fromhex(input('🌱 '))
    key = os.urandom(32)

    cipher = AES(key, seed=seed)

    m0 = os.urandom(16)
    c0 = cipher.encrypt_block(m0)
    print(f'🤐 {c0.hex()}')

    while True:
        m = bytes.fromhex(input('💬 '))
        if m == m0: break
        c = cipher.encrypt_block(m)
        print(f'🤫 {c.hex()}')

    print(f'🏁 {flag}')

if __name__ == '__main__':
    test()
    main()
