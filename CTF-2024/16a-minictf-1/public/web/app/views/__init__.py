from flask import Blueprint, request, jsonify
from flask.views import MethodView
import collections

from app.views import pages
from app.views.api import users
from app.views.api import challenges
from app.views.api.admin import challenges as admin_challenges
from app.models.user import User
from app.models.challenge import Challenge
from app.models.attempt import Attempt


class GroupAPI(MethodView):
    init_every_request = False

    def __init__(self, model):
        self.model = model

        self.name_singular = self.model.__tablename__
        self.name_plural = f'{self.model.__tablename__}s'
    
    def get(self):
        # the users are only able to list the entries related to them
        items = self.model.query_view.all()

        group = request.args.get('group')

        if group is not None and not group.startswith('_') and group in dir(self.model):
            grouped_items = collections.defaultdict(list)
            for item in items:
                id = str(item.__getattribute__(group))
                grouped_items[id].append(item.marshal())
            return jsonify({self.name_plural: grouped_items}), 200

        return jsonify({self.name_plural: [item.marshal() for item in items]}), 200


def register_api(app, model, name):
    group = GroupAPI.as_view(f'{name}_group', model)
    app.add_url_rule(f'/api/{name}/', view_func=group)
    

def init_app(app):
    # Views
    app.register_blueprint(pages.route, url_prefix='/')

    # API
    app.register_blueprint(users.route, url_prefix='/api/users')
    app.register_blueprint(challenges.route, url_prefix='/api/challenges')
    app.register_blueprint(admin_challenges.route, url_prefix='/api/admin/challenges')

    register_api(app, User, 'users')
    register_api(app, Challenge, 'challenges')
    register_api(app, Attempt, 'attempts')
