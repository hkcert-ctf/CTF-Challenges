from flask import Blueprint, request, jsonify, current_app
from http import HTTPStatus, HTTPMethod
from flask_login import login_required, current_user
from datetime import datetime

from app.db import db
from app.limiter import limiter
from app.models.challenge import Challenge
from app.models.attempt import Attempt

route = Blueprint('challenges', __name__)


@route.route('/<int:id>/flag/', methods=[HTTPMethod.POST])
@login_required
@limiter.limit("2/minute")
def submit_flag(id):
    j = request.get_json()
    flag = j.get('flag')

    challenge = Challenge.query.filter_by(id=id).first()
    if challenge is None:
        return jsonify({'error': 'Challenge not found.'}), HTTPStatus.NOT_FOUND

    attempt = Attempt.query_view.filter_by(challenge_id=id, is_correct=True).first()
    if attempt:
        return jsonify({'error': 'You have already solved this challenge.'}), HTTPStatus.BAD_REQUEST

    if not challenge.check_flag(flag):
        attempt = Attempt(
            challenge_id=challenge.id,
            user_id=current_user.id,
            flag=flag,
            is_correct=False,
            submitted_at=datetime.now())

        db.session.add(attempt)
        db.session.commit()
        return jsonify({'error': 'Incorrect flag.'}), HTTPStatus.BAD_REQUEST

    attempt = Attempt(
        challenge_id=challenge.id,
        user_id=current_user.id,
        flag=flag,
        is_correct=True,
        submitted_at=datetime.now())
    
    challenge.solves += 1
    current_user.score += challenge.score

    db.session.add(attempt)
    db.session.add(challenge)
    db.session.add(current_user)

    db.session.commit()

    return jsonify({}), HTTPStatus.OK