from flask_migrate import Migrate


def init_app(app, db):
    migrate = Migrate(app, db.db)
