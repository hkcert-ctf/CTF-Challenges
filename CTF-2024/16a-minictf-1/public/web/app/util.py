import os
import hashlib

from flask import current_app

def compute_hash(password, salt=None):
    if salt is None:
        salt = os.urandom(4).hex()
    return salt + '.' + hashlib.sha256(f'{salt}/{password}'.encode()).hexdigest()
