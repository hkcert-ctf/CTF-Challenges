from flask import Flask
import json
import os

from app import db
from app import views
from app import commands
from app import login_manager
from app import limiter

def create_app():
    app = Flask(__name__)
    app.config.from_file('config.json', load=json.load)
    app.secret_key = os.urandom(24)

    db.init_app(app)
    views.init_app(app)
    commands.init_app(app, db)
    login_manager.init_app(app)
    limiter.init_app(app)

    return app
