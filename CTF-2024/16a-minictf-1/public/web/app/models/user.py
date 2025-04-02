import hashlib
from sqlalchemy import event
from flask import current_app

from app.db import db
from app.util import compute_hash

class _QueryViewProperty:
    def __get__(self, obj, cls):
        return cls.query

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    password = db.Column(db.String, nullable=False)
    score = db.Column(db.Integer, default=0)
    last_solved_at = db.Column(db.DateTime)

    query_view = _QueryViewProperty()

    def marshal(self):
        return {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
            'score': self.score
        }

    # for flask-login
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id

    def check_password(self, password):
        salt, digest = self.password.split('.')
        return compute_hash(password, salt) == self.password

@event.listens_for(User.password, 'set', retval=True)
def hash_user_password(target, value, oldvalue, initiator):
    if value != oldvalue:
        return compute_hash(value)
    return value