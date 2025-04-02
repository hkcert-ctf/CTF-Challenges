from flask_login import current_user

from app.db import db


class _QueryViewProperty:
    def __get__(self, obj, cls):
        if current_user.is_anonymous:
            return cls.query.filter_by(user_id=0)
        return cls.query.filter_by(user_id=current_user.id)

class Attempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    challenge_id = db.Column(db.ForeignKey('challenge.id'), nullable=False)
    user_id = db.Column(db.ForeignKey('user.id'), nullable=False)
    flag = db.Column(db.String, nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)
    submitted_at = db.Column(db.DateTime, nullable=False)

    query_view = _QueryViewProperty()

    def marshal(self):
        return {
            'id': self.id,
            'challenge_id': self.challenge_id,
            'user_id': self.user_id,
            'is_correct': self.is_correct,
        }
