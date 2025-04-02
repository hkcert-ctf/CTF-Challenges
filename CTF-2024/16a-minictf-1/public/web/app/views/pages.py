from flask import Blueprint, request, jsonify, render_template, flash, url_for, redirect
from http import HTTPStatus, HTTPMethod
from wtforms_sqlalchemy.orm import model_form
from flask_login import login_user, logout_user, current_user

from app.db import db
from app.limiter import limiter
from app.models.user import User

route = Blueprint('pages', __name__)


@route.route('/', methods=[HTTPMethod.GET])
def homepage():
    return render_template('homepage.html', current_user=current_user), HTTPStatus.OK

@route.route('/register/', methods=[HTTPMethod.GET])
def register():
    return render_template('register.html'), HTTPStatus.OK

@route.route('/register/', methods=[HTTPMethod.POST])
def register_submit():
    user = User()
    UserForm = model_form(User)

    form = UserForm(request.form, obj=user)

    if not form.validate():
        flash('Invalid input', 'warning')
        return redirect(url_for('pages.register'))

    form.populate_obj(user)

    user_with_same_username = User.query_view.filter_by(username=user.username).first()
    if user_with_same_username is not None:
        flash('User with the same username exists.', 'warning')
        return redirect(url_for('pages.register'))

    db.session.add(user)
    db.session.commit()

    login_user(user)
    return redirect(url_for('pages.homepage'))

@route.route('/login/', methods=[HTTPMethod.GET])
def login():
    return render_template('login.html'), HTTPStatus.OK

@route.route('/login/', methods=[HTTPMethod.POST])
@limiter.limit("2/minute")
def login_submit():
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query_view.filter_by(username=username).first()
    if user is None:
        flash('User not found.', 'warning')
        return redirect(url_for('pages.login'))

    if not user.check_password(password):
        flash('Invalid password.', 'warning')
        return redirect(url_for('pages.login'))

    login_user(user)
    return redirect(url_for('pages.homepage'))

@route.route('/logout/', methods=[HTTPMethod.GET])
def logout():
    logout_user()
    return redirect(url_for('pages.homepage'))

@route.route('/challenges/', methods=[HTTPMethod.GET])
def list_challenges():
    return render_template('challenges.html'), HTTPStatus.OK

@route.route('/scoreboard/', methods=[HTTPMethod.GET])
def scoreboard():
    return render_template('scoreboard.html'), HTTPStatus.OK

@route.route('/admin/challenges/', methods=[HTTPMethod.GET])
def manage_challenges():
    if not current_user.is_authenticated:
        flash('You are not logged in.', 'warning')
        return redirect(url_for('pages.login'))

    if not current_user.is_admin:
        return render_template('403.html'), HTTPStatus.FORBIDDEN

    return render_template('admin/challenges.html'), HTTPStatus.OK
