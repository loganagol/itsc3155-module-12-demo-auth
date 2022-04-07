import os

from dotenv import load_dotenv
from flask import Flask, abort, redirect, render_template, request, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

load_dotenv()

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('SECRET_KEY')


bcrypt = Bcrypt(app)
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'app_user'

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)

    def __init__(self, username, password) -> None:
        self.username = username
        self.password = password


@app.get('/')
def index():
    if 'user' in session:
        return redirect('/success')
    return render_template('index.html')


@app.get('/register')
def get_register_page():
    if 'user' in session:
        return redirect('/success')
    return render_template('register.html')


@app.post('/register')
def register():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    if username == '' or password == '':
        abort(400)

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = User(username, hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return redirect('/')


@app.post('/login')
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    if username == '' or password == '':
        abort(400)

    existing_user = User.query.filter_by(username=username).first()

    if not existing_user or existing_user.user_id == 0:
        return redirect('/fail')

    if not bcrypt.check_password_hash(existing_user.password, password):
        return redirect('/fail')

    session['user'] = {
        'username': username,
        'user_id': existing_user.user_id,
    }

    return redirect('/success')


@app.get('/success')
def success():
    if not 'user' in session:
        abort(401)
    return render_template('success.html', user=session['user']['username'])


@app.get('/fail')
def fail():
    if 'user' in session:
        return redirect('/success')
    return render_template('fail.html')


@app.post('/logout')
def logout():
    if 'user' not in session:
        abort(401)

    del session['user']

    return redirect('/')
