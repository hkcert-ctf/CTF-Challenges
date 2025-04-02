from flask_login import LoginManager

from app.models.user import User

login_manager = LoginManager()


def init_app(app):
    login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()
