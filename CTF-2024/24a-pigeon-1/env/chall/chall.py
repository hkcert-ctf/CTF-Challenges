import json
import hashlib
import os
import secrets
from Crypto.Cipher import AES
import re

# This is the parameter specified in RFC-3526. Let's assume this is safe :)
# https://datatracker.ietf.org/doc/html/rfc3526#section-3
P = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
G = 0x2

class User:
    def __init__(self, id, secret=None, other_secret=None):
        self.id = id
        self.secret = secret
        self.other_secret = other_secret

        self.private_key = None
        self.session_key = None

        pass

    # Message handler
    def handle_message(self, message):
        message = json.loads(message)
        type_ = message.get('type')
        if type_ == 'init_handshake':
            res = self.init_handshake()
        elif type_ == 'receive_handshake':
            other_public_key = message.get('public_key')
            res = self.receive_handshake(other_public_key)
        elif type_ == 'finish_handshake':
            other_public_key = message.get('public_key')
            res = self.finish_handshake(other_public_key)
        elif type_ == 'communicate':
            ciphertext = bytes.fromhex(message.get('ciphertext'))
            res = self.communicate(ciphertext)
        else:
            raise Exception(f'unknown message type {type_}')

        return json.dumps(res, separators=(',', ':'))

    # ===

    # Phase 1: Handshaking

    def init_handshake(self):
        assert self.private_key is None

        self.private_key = secrets.randbelow(P)
        self.public_key = pow(G, self.private_key, P)
        return {
            "type": "receive_handshake",
            "public_key": self.public_key
        }

    def receive_handshake(self, other_public_key):
        assert self.private_key is None
        assert self.session_key is None

        self.private_key = secrets.randbelow(P)
        self.public_key = pow(G, self.private_key, P)

        self.session_key = derive_session_key(other_public_key, self.private_key)

        return {
            "type": "finish_handshake",
            "public_key": self.public_key
        }

    def finish_handshake(self, other_public_key):
        assert self.session_key is None

        self.session_key = derive_session_key(other_public_key, self.private_key)
        
        message = b'done!'
        ciphertext = encrypt_message(self.session_key, message)

        return {
            "type": "communicate",
            "ciphertext": ciphertext.hex()
        }

    # Phase 2: Encrypted communication

    def communicate(self, incoming_ciphertext):
        incoming_message = decrypt_message(self.session_key, incoming_ciphertext)

        # message handler
        if self.id == 'Byron':
            if incoming_message == b'done!':
                outgoing_message = f'what is the flag? I have the secret {self.secret}'.encode()
            elif incoming_message.startswith(b'the flag is '):
                flag = incoming_message[12:].strip()
                if re.match(br'hkcert24{.*}', flag):
                    outgoing_message = b'nice flag!'
                else:
                    outgoing_message = b'too bad...'
            else:
                outgoing_message = b'???'
        elif self.id == 'Alice':
            if incoming_message == f'what is the flag? I have the secret {self.other_secret}'.encode():
                outgoing_message = f'the flag is {self.secret}'.encode()
            elif incoming_message == b'nice flag!':
                outgoing_message = b':)'
            elif incoming_message == b'too bad...':
                outgoing_message = b'what happened?'
            else:
                outgoing_message = b'???'

        outgoing_ciphertext = encrypt_message(self.session_key, outgoing_message)

        return {
            "type": "communicate",
            "ciphertext": outgoing_ciphertext.hex()
        }

# Utility functions

def derive_session_key(other_public_key, self_private_key):
    shared_key = pow(other_public_key, self_private_key, P)
    session_key = hashlib.sha256(shared_key.to_bytes(512, 'big')).digest()
    return session_key

def encrypt_message(session_key: bytes, message: bytes):
    nonce = os.urandom(8)
    cipher = AES.new(session_key, AES.MODE_CTR, nonce=nonce)
    return nonce + cipher.encrypt(message)

def decrypt_message(session_key: bytes, ciphertext: bytes):
    nonce, ciphertext = ciphertext[:8], ciphertext[8:]
    cipher = AES.new(session_key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)


def main():
    flag = os.environ.get('FLAG', 'hkcert24{***REDACTED***}')
    token = os.urandom(8).hex()

    alice = User('Alice', flag, token)
    byron = User('Byron', token)

    res = alice.handle_message('{"type":"init_handshake"}')
    print(res)

    while True:
        command, *args = input('🕊️  ').strip().split(' ')

        if command == 'alice':
            # send a message to Alice
            content, = args
            print(alice.handle_message(content))

        elif command == 'byron':
            # send a message to Byron
            content, = args
            print(byron.handle_message(content))


if __name__ == '__main__':
    try:
        main()
    except:
        print('😡')
