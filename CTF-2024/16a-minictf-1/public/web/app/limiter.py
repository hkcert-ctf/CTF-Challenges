from http import HTTPStatus
from flask import make_response, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(get_remote_address)


def init_app(app):
    limiter.init_app(app)

    @app.errorhandler(429)
    def rate_limit_error_handler(e):
        return make_response(jsonify({'error': 'You are sending too many requests. Please slow down.'}), HTTPStatus.TOO_MANY_REQUESTS)
