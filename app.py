# import all need
import functools
from datetime import datetime, timezone
from time import time

import jwt

from flask import Flask

from flask_mail import Message
from flask_mail import Mail

from flask_login import LoginManager, UserMixin

from flask_sqlalchemy import SQLAlchemy

from flask_migrate import Migrate

from flask import redirect, url_for, render_template, flash, request

from flask_login import login_required, current_user, login_user, logout_user

import sqlalchemy as sa
import sqlalchemy.orm as so

from urllib.parse import urlsplit

from werkzeug.security import generate_password_hash, check_password_hash

from typing import Optional

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.fields.simple import TextAreaField
from wtforms.validators import DataRequired, EqualTo, ValidationError, Email

import os
from dotenv import load_dotenv

# init

app = Flask(__name__)

app.secret_key = os.getenv('FLASK-SECRET-KEY')

login_manager = LoginManager()
login_manager.init_app(app)

app.config['SQLALCHEMY_DATABASE_URI'] = (f"mysql://{os.getenv('DB-USERNAME')}:{os.getenv('DB-PASSWORD')}"
                                         f"@{os.getenv('DB-URL')}/{os.getenv('DB-NAME')}")
db = SQLAlchemy(app)

migrate = Migrate(app, db)

mail = Mail(app)

load_dotenv()

mail.MAIL_SERVER = os.getenv('MAIL_SERVER')
mail.MAIL_USE_TLS = os.getenv('MAIL_USE_TLS')
mail.MAIL_USERNAME = os.getenv('MAIL_USERNAME')
mail.MAIL_DEFAULT_SENDER = os.getenv('MAIL_USERNAME')
mail.MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
mail.MAIL_PORT = os.getenv('MAIL_PORT')

# decorators


def admin_required(func):
    @functools.wraps(func)
    def _wrapper(*args, **kwargs):
        if current_user.is_admin():
            return func(*args, **kwargs)
        else:
            return error_403('')
    return _wrapper

# send mail


def send_email(subject, sender, recipients, text_body, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.body = text_body
    msg.html = html_body
    mail.send(msg)


def send_password_reset_email(user):
    token = user.get_reset_password_token()
    send_email('[lime.run.place] Сброс пароля',
               sender=os.getenv('MAIL_USERNAME'),
               recipients=[user.email],
               text_body=render_template('email/reset_password.txt',
                                         user=user, token=token),
               html_body=render_template('email/reset_password.html',
                                         user=user, token=token))

# routes


@app.route('/')
@app.route('/home')
@app.route('/index')
def index():
    return render_template('index.html', name="Главная")


@app.route('/about-me')
def about_me():
    return render_template('about_me.html', name="Обо мне")


@app.route('/discord-server')
def discord_server():
    return render_template('discord_server.html', name="Discord сервер")


@app.route('/blog')
def blog():
    return render_template('blog.html', pages=[], name="Блог")


@app.route('/admin')
@login_required
@admin_required
def admin():
    return render_template('admin.html', name="Админ-панель")


@app.route('/new-post', methods=['POST', 'GET'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(post_name=form.post_name.data, body=form.post.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('blog'))
    return render_template('new_post.html', form=form, name='Новый пост')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, level=0, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Вы зарегистрированны!')
        return redirect(url_for('login'))
    return render_template('register.html', name='Регистрация', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.username == form.username.data))
        if user is None or not user.check_password(form.password.data):
            flash('Неверное имя пользователя или пароль!', 'info')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('blog')
        return redirect(next_page)
    return render_template('login.html', form=form, name="Вход")


@app.route('/logout', methods=['GET'])
def logout():
    logout_user()
    next_page = request.args.get('next')
    if not next_page or urlsplit(next_page).netloc != '':
        next_page = url_for('blog')
    return redirect(next_page)


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.email == form.email.data))
        if user:
            send_password_reset_email(user)
        flash('Проверь почту')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html',
                           title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)


# errors

@app.errorhandler(401)
def error_401(error):
    return render_template('401.html', name="Ошибка 401"), 401


@app.errorhandler(404)
def error_404(error):
    return render_template('404.html', name="Ошибка 404"), 404


@app.errorhandler(403)
def error_403(error):
    return render_template('4z03.html', name="Ошибка 403"), 403


# db


class User(UserMixin, db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), index=True, unique=True)
    email: so.Mapped[Optional[str]] = so.mapped_column(sa.String(120), index=True, unique=True)
    password_hash: so.Mapped[Optional[str]] = so.mapped_column(sa.String(256))
    posts: so.WriteOnlyMapped['Post'] = so.relationship(
        back_populates='author')
    level: so.Mapped[int] = so.mapped_column()

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return db.session.get(User, id)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def change_level(self, level):
        self.level = level

    def is_admin(self):
        return db.session.scalar(sa.select(User.level).where(User.id == self.id)) == 1

    def __repr__(self):
        return '<User {}>'.format(self.username)


class Post(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    post_name: so.Mapped[str] = so.mapped_column(sa.String(50))
    body: so.Mapped[str] = so.mapped_column(sa.String(1000))
    timestamp: so.Mapped[datetime] = so.mapped_column(
        index=True, default=lambda: datetime.now(timezone.utc))
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey(User.id),
                                               index=True)

    author: so.Mapped[User] = so.relationship(back_populates='posts')

    def __repr__(self):
        return '<Post {}>'.format(self.body)


# forms


class LoginForm(FlaskForm):
    username = StringField("Имя: ", validators=[DataRequired()])
    password = PasswordField("Пароль: ", validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField("Войти")


class RegistrationForm(FlaskForm):
    email = StringField('Почта (необязательно, требуется для восстановления пароля):', validators=[Email()])
    username = StringField('Имя:', validators=[DataRequired()])
    password = PasswordField('Пароль:', validators=[DataRequired()])
    password2 = PasswordField(
        'Повторите пароль:', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        user = db.session.scalar(sa.select(User).where(User.username == username.data))
        if user is not None:
            raise ValidationError('Используй другое имя!')

    def validate_email(self, email):
        user = db.session.scalar(sa.select(User).where(User.email == email.data))
        if user is not None:
            raise ValidationError('Используй другую почту!')


class PostForm(FlaskForm):
    post_name = StringField('Название статьи (отображается в списке статей и самой статье)', validators=[DataRequired()])
    post = TextAreaField('Текст статьи', validators=[
        DataRequired()])
    submit = SubmitField('Опубликовать')


class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Ваша почта, на которую придёт письмо', validators=[DataRequired(), Email()])
    submit = SubmitField('Отправить запрос на восстановление пароля')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Пароль:', validators=[DataRequired()])
    password2 = PasswordField(
        'Повтори пароль:', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Сменить пароль')


# load user

@login_manager.user_loader
def load_user(id):
    return db.session.get(User, int(id))


# run app

if __name__ == "__main__":
    # uncomment if you need

    # for server use:
    # from waitress import serve
    # serve(app, host="::1", _quiet=False)

    # for tests:
    app.run(host="0.0.0.0", port=80, debug=True)
