from flask import Flask, request, jsonify, session, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
from functools import wraps
import os
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # change this to secure random value
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_CHECK_DEFAULT'] = False  # We'll manually check CSRF for API

db = SQLAlchemy(app)
CORS(app, supports_credentials=True, origins=["http://localhost:5000"])
csrf = CSRFProtect(app)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    balance = db.Column(db.Float, default=100.0)  # <-- Added balance column

    cart_items = db.relationship('CartItem', backref='user', lazy=True)
    orders = db.relationship('Order', backref='user', lazy=True)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    price = db.Column(db.Float, nullable=False)


class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    product = db.relationship('Product')


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    items = db.Column(db.Text, nullable=False)  # comma-separated product names

# --- Helpers ---
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

# --- Routes ---
@app.route('/api/signup', methods=['POST'])
@csrf.exempt
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created'}), 201

@app.route('/api/login', methods=['POST'])
@csrf.exempt
def login():
    data = request.json
    user = User.query.filter_by(username=data.get('username')).first()
    if not user or user.password != data.get('password'):
        return jsonify({'error': 'Invalid credentials'}), 401

    session['user_id'] = user.id
    session['username'] = user.username
    return jsonify({'message': 'Logged in'})

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({'message': 'Logged out'})

@app.route('/api/products', methods=['GET'])
@login_required
def get_products():
    products = Product.query.all()
    return jsonify([{'id': p.id, 'name': p.name, 'price': p.price} for p in products])

@app.route('/api/cart', methods=['GET', 'POST', 'DELETE'])
@login_required
@csrf.exempt
def cart():
    user = User.query.get(session['user_id'])

    if request.method == 'GET':
        items = CartItem.query.filter_by(user_id=user.id).all()
        return jsonify([{'id': item.product.id, 'name': item.product.name, 'price': item.product.price} for item in items])

    elif request.method == 'POST':
        product_id = request.json.get('product_id')
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': 'Product not found'}), 404

        item = CartItem(user_id=user.id, product_id=product.id)
        db.session.add(item)
        db.session.commit()
        return jsonify({'message': 'Added to cart'})

    elif request.method == 'DELETE':
        CartItem.query.filter_by(user_id=user.id).delete()
        db.session.commit()
        return jsonify({'message': 'Cart cleared'})

@app.route('/api/orders', methods=['GET', 'POST'])
@login_required
@csrf.exempt
def orders():
    user = User.query.get(session['user_id'])

    if request.method == 'GET':
        return jsonify([
            {'id': o.id, 'items': o.items.split(',')}
            for o in Order.query.filter_by(user_id=user.id).all()
        ])

    elif request.method == 'POST':
        cart_items = CartItem.query.filter_by(user_id=user.id).all()
        if not cart_items:
            return jsonify({'error': 'Cart is empty'}), 400

        product_names = [item.product.name for item in cart_items]
        order = Order(user_id=user.id, items=",".join(product_names))
        db.session.add(order)
        CartItem.query.filter_by(user_id=user.id).delete()
        db.session.commit()
        return jsonify({'message': 'Order placed', 'order': {'id': order.id, 'items': product_names}})

@app.route('/api/user-info', methods=['GET'])
@login_required
def user_info():
    user = User.query.get(session['user_id'])
    return jsonify({'username': user.username, 'balance': user.balance})

# --- Deposit route ---
BLOCKCYPHER_TOKEN = "dbd5a9f9a6b5403a8c0171bd25b5e883"
BLOCKCYPHER_API_URL = "https://api.blockcypher.com/v1/btc/test3"

@app.route('/api/deposit', methods=['POST'])
@login_required
@csrf.exempt
def deposit():
    user = User.query.get(session['user_id'])
    data = request.json
    amount = data.get('amount')

    try:
        amount = float(amount)
        if amount <= 0:
            return jsonify({'error': 'Deposit amount must be positive'}), 400
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid amount'}), 400

    # Simulate deposit verification with BlockCypher API here if needed

    user.balance += amount
    db.session.commit()
    return jsonify({'message': f'Deposited ${amount:.2f}', 'new_balance': user.balance})

# --- CSRF Token Fetch Route ---
@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    token = csrf.generate_csrf()
    return jsonify({'csrf_token': token})

# --- Manual DB Initialization Route ---
@app.route('/init_db')
def init_db():
    db.create_all()
    if not Product.query.first():
        db.session.add_all([
            Product(name='Apple', price=1.0),
            Product(name='Banana', price=0.5),
            Product(name='Orange', price=0.75)
        ])
        db.session.commit()
    return "Database initialized!"

if __name__ == '__main__':
    app.run(debug=True)
