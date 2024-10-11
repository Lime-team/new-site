# import all need
from flask import Flask, redirect, url_for, render_template, flash, make_response

from flask_login import LoginManager, UserMixin, login_required

from blog_users_manage import *

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, BooleanField, PasswordField
from wtforms.validators import DataRequired, Email, Length

import os
from dotenv import load_dotenv

# init

app = Flask(__name__)

app.secret_key = os.getenv('FLASK-SECRET-KEY')

login_manager = LoginManager()
login_manager.init_app(app)

load_dotenv()

create_table()

# user login class


def get(user_id):
    get_user(user_id)


class User(UserMixin):
    def __init__(self, name, password):
        super().__init__()
        if get_id(name) is None:
            add_user(name, password)


# users login


class LoginForm(FlaskForm):
    email = StringField("Имя: ", validators=[DataRequired()])
    psw = PasswordField("Пароль: ", validators=[DataRequired()])
    submit = SubmitField("Войти")


@login_manager.user_loader
def load_user(user_id):
    return get(user_id)


# pages


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/home')
def home():
    return redirect(url_for('index'))


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
# @login_required
def admin():
    return render_template('admin.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Здесь мы используем некий класс для представления и проверки наших
    # данных формы на стороне клиента. Например, WTForms — это библиотека, которая
    # обрабатывает это за нас, и мы используем специальную форму входа для проверки.
    form = LoginForm()
    if form.validate_on_submit():
        # Login и подтвердите пользователя.
        # пользователь должен быть экземпляром вашего класса User

        flash('Успешный вход.')

        return redirect(url_for('admin'))
    return render_template('login.html', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.errorhandler(401)
def error_401(error):
    return render_template('401.html')


@app.errorhandler(404)
def error_404(error):
    return render_template('404.html')


# run app

if __name__ == "__main__":

    # uncomment if you need

    # for server use:
    # from waitress import serve
    # serve(app, host="::1", port=80, _quiet=False)

    # for tests:
    app.run(host="::", port=80, debug=True)
