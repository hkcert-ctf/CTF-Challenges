from flask import Blueprint, jsonify
from http import HTTPStatus, HTTPMethod
from flask_login import login_required, current_user

from app.db import db
from app.models.challenge import Challenge


route = Blueprint('admin_challenges', __name__)


@route.route('/', methods=[HTTPMethod.GET])
@login_required
def list_challenges():
    if not current_user.is_admin:
        return jsonify({'error': 'not an admin'}), HTTPStatus.FORBIDDEN

    challenges = Challenge.query.all()

    return jsonify({
        'challenges': [challenge.admin_marshal() for challenge in challenges]
    }), HTTPStatus.OK


'''
NOTE: The below APIs are intentionally unimplemented - and it will not be given
even in an official release. Why? A good cybersecurity professional should know
how to compose SQL queries and update the challenges there :) /s
'''

@route.route('/', methods=[HTTPMethod.POST])
@login_required
def create_challenge():
    if not current_user.is_admin:
        return jsonify({'error': 'not an admin'}), HTTPStatus.FORBIDDEN

    return jsonify({'error': 'not implemented'}), HTTPStatus.NOT_IMPLEMENTED


@route.route('/:id/', methods=[HTTPMethod.DELETE])
@login_required
def delete_challenge():
    if not current_user.is_admin:
        return jsonify({'error': 'not an admin'}), HTTPStatus.FORBIDDEN

    return jsonify({'error': 'not implemented'}), HTTPStatus.NOT_IMPLEMENTED


@route.route('/:id/', methods=[HTTPMethod.GET])
@login_required
def get_challenge():
    if not current_user.is_admin:
        return jsonify({'error': 'not an admin'}), HTTPStatus.FORBIDDEN

    return jsonify({'error': 'not implemented'}), HTTPStatus.NOT_IMPLEMENTED


@route.route('/:id/', methods=[HTTPMethod.POST])
@login_required
def update_challenge():
    if not current_user.is_admin:
        return jsonify({'error': 'not an admin'}), HTTPStatus.FORBIDDEN

    return jsonify({'error': 'not implemented'}), HTTPStatus.NOT_IMPLEMENTED
