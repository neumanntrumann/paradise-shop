from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt
import datetime
import functools
import secrets

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///paradise_shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_jwt(self):
        payload = {
            'user_id': self.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        if isinstance(token, bytes):
            token = token.decode('utf-8')
        return token

# CSRF protection
def generate_csrf_token():
    return secrets.token_urlsafe(32)

def verify_csrf():
    csrf_cookie = request.cookies.get('csrf_token')
    csrf_header = request.headers.get('X-CSRF-Token')
    return csrf_cookie and csrf_header and csrf_cookie == csrf_header

def csrf_protect(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "POST":
            if not verify_csrf():
                return jsonify({'error': 'CSRF token missing or invalid'}), 403
        return f(*args, **kwargs)
    return decorated

# JWT verification
def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]
        if not token:
            token = request.cookies.get('jwt')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(payload['user_id'])
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Web login required decorator
def login_required_redirect(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('jwt')
        if not token:
            return redirect(url_for('login_page'))
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(payload['user_id'])
            if not current_user:
                return redirect(url_for('login_page'))
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return redirect(url_for('login_page'))
        return f(current_user, *args, **kwargs)
    return decorated

# Routes

@app.route('/')
def root():
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET'])
def login_page():
    csrf_token = generate_csrf_token()
    resp = make_response(render_template('index.html'))  # login page is now index.html
    resp.set_cookie('csrf_token', csrf_token, httponly=False, samesite='Lax')
    return resp

@app.route('/login.html')
def login_html_redirect():
    return redirect(url_for('login_page'))

@app.route('/signup', methods=['GET'])
def signup_page():
    csrf_token = generate_csrf_token()
    resp = make_response(render_template('signup.html'))
    resp.set_cookie('csrf_token', csrf_token, httponly=False, samesite='Lax')
    return resp

@app.route('/login', methods=['POST'])
@csrf_protect
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid username or password'}), 401

    token = user.generate_jwt()
    resp = jsonify({'message': 'Login successful'})
    resp.set_cookie('jwt', token, httponly=True, samesite='Lax')
    return resp

@app.route('/signup', methods=['POST'])
@csrf_protect
def signup():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already taken'}), 409

    hashed_pw = generate_password_hash(password)
    new_user = User(username=username, password_hash=hashed_pw)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'})

@app.route('/profile')
@token_required
def profile(current_user):
    return jsonify({'username': current_user.username})

@app.route('/home')  # updated from /index
@login_required_redirect
def home_page(current_user):
    return render_template('home.html', username=current_user.username)

@app.route('/balance')
@login_required_redirect
def balance_page(current_user):
    return render_template('balance.html', username=current_user.username)

@app.route('/marketplace')
@login_required_redirect
def marketplace_page(current_user):
    return render_template('marketplace.html', username=current_user.username)

@app.route('/cart')
@login_required_redirect
def cart_page(current_user):
    return render_template('cart.html', username=current_user.username)

@app.route('/orders')
@login_required_redirect
def orders_page(current_user):
    return render_template('orders.html', username=current_user.username)

@app.route('/more')
@login_required_redirect
def more_page(current_user):
    return render_template('more.html', username=current_user.username)

@app.route('/logout')
def logout():
    resp = redirect(url_for('login_page'))
    resp.delete_cookie('jwt')
    return resp

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
