# import all need
from datetime import datetime, timezone

from flask import Flask

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
from wtforms.validators import DataRequired, EqualTo, ValidationError

import os
from dotenv import load_dotenv

# init

app = Flask(__name__)

app.secret_key = os.getenv('FLASK-SECRET-KEY')

login_manager = LoginManager()
login_manager.init_app(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(
    os.path.dirname(__file__)), 'app.db')
db = SQLAlchemy(app)
migrate = Migrate(app, db)

load_dotenv()

# routes


@app.route('/')
@app.route('/home')
@app.route('/index')
def index():
    return render_template('index.html', name="Главная")


@app.route('/about-me')
def about_me():
    return render_template('about_me.html')


@app.route('/discord-server')
def discord_server():
    return render_template('discord_server.html')


@app.route('/blog')
def blog():
    return render_template('blog.html', pages=['static/blog_files/a.html'])


@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
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
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('blog'))


# errors

@app.errorhandler(401)
def error_401(error):
    return render_template('401.html')


@app.errorhandler(404)
def error_404(error):
    return render_template('404.html')


# db


class User(UserMixin, db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), index=True, unique=True)
    password_hash: so.Mapped[Optional[str]] = so.mapped_column(sa.String(256))
    posts: so.WriteOnlyMapped['Post'] = so.relationship(
        back_populates='author')
    level: so.Mapped[int] = so.mapped_column()

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)


class Post(db.Model):
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    post_name: so.Mapped[str] = so.mapped_column(sa.String(50))
    body: so.Mapped[str] = so.mapped_column(sa.String())
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
    username = StringField('Имя:', validators=[DataRequired()])
    password = PasswordField('Пароль:', validators=[DataRequired()])
    password2 = PasswordField(
        'Повторите пароль:', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        user = db.session.scalar(sa.select(User).where(
            User.username == username.data))
        if user is not None:
            raise ValidationError('Используй другое имяs')


# load user

@login_manager.user_loader
def load_user(id):
    return db.session.get(User, int(id))


# run app

if __name__ == "__main__":
    # uncomment if you need

    # for server use:
    # from waitress import serve
    # serve(app, host="::1", port=80, _quiet=False)

    # for tests:
    app.run(host="0.0.0.0", port=80, debug=True)
