from flask import Flask
from flask import request
import os
import hashlib
from Crypto.Cipher import AES

app = Flask(__name__)

@app.route("/", methods=['POST'])
def index():
    nonce = request.json.get('nonce')
    if nonce is None:
        return '', 400

    try:
        nonce = bytes.fromhex(nonce)
    except:
        return '', 400

    if hashlib.sha256(b'pow/' + nonce).digest()[:3] != b'\0\0\0':
        return '', 400

    key = hashlib.sha256(b'key/' + nonce).digest()[:16]
    iv = hashlib.sha256(b'iv/' + nonce).digest()[:16]

    cipher = AES.new(key, AES.MODE_CFB, iv)

    FLAG = os.environb.get(b'FLAG', b'hkcert24{***REDACTED***}')
    c = cipher.encrypt(FLAG)
    return c.hex(), 200