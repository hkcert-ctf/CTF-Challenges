from flask import Blueprint, jsonify
from http import HTTPStatus, HTTPMethod
from flask_login import login_required, current_user

from app.models.user import User


route = Blueprint('users', __name__)


@route.route('/me/', methods=[HTTPMethod.GET])
@login_required
def get_me():
    return jsonify({'user': current_user.marshal()}), HTTPStatus.OK


@route.route('/<int:id>/', methods=[HTTPMethod.GET])
def get_user(id):
    user = User.query_view.filter_by(id=id).first()
    if user is None:
        return jsonify({'error': 'user not found'}), HTTPStatus.NOT_FOUND

    return jsonify({'user': user.marshal()}), HTTPStatus.OK


@route.route('/top/', methods=[HTTPMethod.GET])
def list_top_players():
    users = User.query_view.order_by(User.score.desc(), User.last_solved_at.asc()).limit(10).all()
    return jsonify({'users': [user.marshal() for user in users]}), HTTPStatus.OK
