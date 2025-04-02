from flask import Blueprint, request, jsonify
from flask.views import MethodView
import collections


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
    app.add_url_rule(f'/{name}/', view_func=group)
