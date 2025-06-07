from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import os
import functools

app = Flask(__name__)

# Enable CORS, allow your frontend origin, support cookies (credentials)
CORS(app, supports_credentials=True, origins=["http://localhost:5000"])

# Configuration
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', '6LeaIlYrAAAAADtcb41HN1b4oS49g_hz_TfisYpZ')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///paradise_shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production (https)

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Decorator for web routes that require login

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return redirect('/login')
        user = User.query.get(user_id)
        if not user:
            return redirect('/login')
        return f(user, *args, **kwargs)
    return decorated

# Routes
@app.route('/')
def root():
    return redirect('/login')

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid username or password'}), 401

    session['user_id'] = user.id
    return jsonify({'message': 'Login successful'})

@app.route('/signup', methods=['POST'])
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
@login_required
def profile(current_user):
    return jsonify({'username': current_user.username})

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# --- Protected pages ---
@app.route('/index')
@login_required
def index_page(current_user):
    return render_template('index.html', username=current_user.username)

@app.route('/home')
@login_required
def home_page(current_user):
    return render_template('index.html', username=current_user.username)

@app.route('/balance')
@login_required
def balance_page(current_user):
    return render_template('balance.html', username=current_user.username)

@app.route('/marketplace')
@login_required
def marketplace_page(current_user):
    return render_template('marketplace.html', username=current_user.username)

@app.route('/cart')
@login_required
def cart_page(current_user):
    return render_template('cart.html', username=current_user.username)

@app.route('/checkout')
@login_required
def checkout_page(current_user):
    return render_template('checkout.html', username=current_user.username)

@app.route('/orders')
@login_required
def orders_page(current_user):
    return render_template('orders.html', username=current_user.username)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
