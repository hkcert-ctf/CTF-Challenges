import hashlib
from sqlalchemy import event
import enum
from datetime import datetime

from app.db import db
from app.util import compute_hash

class Category(enum.Enum):
    CRYPTO = 1
    WEB = 2
    REVERSE = 3
    PWN = 4
    FORENSICS = 5
    MISC = 6

    def __str__(self):
        return self.name.lower()


class _QueryViewProperty:
    def __get__(self, obj, cls):
        return cls.query.filter(cls.released_at <= datetime.now())

class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    category = db.Column(db.Enum(Category), nullable=False)
    flag = db.Column(db.String, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    solves = db.Column(db.Integer, nullable=False)
    released_at = db.Column(db.DateTime, nullable=False)

    query_view = _QueryViewProperty()

    def marshal(self):
        return {
            'id': self.id,
            'category': str(self.category),
            'title': self.title,
            'description': self.description,
            'score': self.score,
            'solves': self.solves,
            'released_at': self.released_at
        }

    def admin_marshal(self):
        return {
            'id': self.id,
            'category': str(self.category),
            'title': self.title,
            'description': self.description,
            'flag': self.flag,
            'score': self.score,
            'solves': self.solves,
            'released_at': self.released_at
        }

    def check_flag(self, flag):
        salt, digest = self.flag.split('.')
        return compute_hash(flag, salt) == self.flag

@event.listens_for(Challenge.flag, 'set', retval=True)
def hash_challenge_flag(target, value, oldvalue, initiator):
    if value != oldvalue:
        return compute_hash(value)
    return value