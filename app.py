from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os, jwt, datetime, functools, secrets

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///paradise_shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    join_date = db.Column(db.String(50))
    cart_items = db.relationship('CartItem', backref='user', lazy=True)
    orders = db.relationship('Order', backref='user', lazy=True)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_jwt(self):
        payload = {
            'user_id': self.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        return token.decode('utf-8') if isinstance(token, bytes) else token

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    price = db.Column(db.Float)
    quantity = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    items = db.relationship('OrderItem', backref='order', lazy=True)

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    price = db.Column(db.Float)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))

# CSRF Protection
def generate_csrf_token():
    return secrets.token_urlsafe(32)

def verify_csrf():
    return request.cookies.get('csrf_token') == request.headers.get('X-CSRF-Token')

def csrf_protect(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "POST" and not verify_csrf():
            return jsonify({'error': 'CSRF token missing or invalid'}), 403
        return f(*args, **kwargs)
    return decorated

# Token Authentication
def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token and token.startswith('Bearer '):
            token = token[7:]
        else:
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

# Your requested login_required decorator with redirects using flask's wraps and jwt decode
from functools import wraps
from flask import request, redirect, url_for, render_template, make_response
import jwt

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return redirect(url_for('login_page'))
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return redirect(url_for('login_page'))
        except jwt.InvalidTokenError:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# Route to serve checkout.html, protected by login_required
@app.route('/checkout')
@login_required
def checkout_page():
    return render_template('checkout.html')

# Routes
@app.route('/')
def root():
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET'])
def login_page():
    csrf_token = generate_csrf_token()
    resp = make_response(render_template('index.html'))
    resp.set_cookie('csrf_token', csrf_token, httponly=False, samesite='Lax')
    return resp

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

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        token = user.generate_jwt()
        resp = jsonify({'message': 'Login successful'})
        resp.set_cookie('jwt', token, httponly=True, samesite='Lax')
        return resp
    return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/signup', methods=['POST'])
@csrf_protect
def signup():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already taken'}), 409

    hashed_pw = generate_password_hash(password)
    new_user = User(
        username=username,
        password_hash=hashed_pw,
        join_date=datetime.datetime.utcnow().strftime('%Y-%m-%d')
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'})

@app.route('/logout')
def logout():
    resp = redirect(url_for('login_page'))
    resp.delete_cookie('jwt')
    return resp

# HTML PAGES
@app.route('/home')
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

# API ENDPOINTS
@app.route('/api/user/profile')
@token_required
def profile(current_user):
    orders = Order.query.filter_by(user_id=current_user.id).all()
    total_spent = sum(sum(item.price for item in order.items) for order in orders)
    return jsonify({
        'username': current_user.username,
        'balance': current_user.balance,
        'totalSpent': total_spent,
        'joinDate': current_user.join_date,
        'orderCount': len(orders)
    })

@app.route('/api/userdata')
@token_required
def userdata(current_user):
    cart = CartItem.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        'cart': [{
            'id': item.id,
            'name': item.name,
            'price': item.price,
            'quantity': item.quantity
        } for item in cart]
    })

@app.route('/api/cart/item/<int:item_id>', methods=['DELETE'])
@token_required
def remove_cart_item(current_user, item_id):
    item = CartItem.query.filter_by(id=item_id, user_id=current_user.id).first()
    if item:
        db.session.delete(item)
        db.session.commit()
        return jsonify({'message': 'Item removed'})
    return jsonify({'error': 'Item not found'}), 404

@app.route('/api/checkout', methods=['POST'])
@token_required
def checkout(current_user):
    cart = CartItem.query.filter_by(user_id=current_user.id).all()
    if not cart:
        return jsonify({'error': 'Cart is empty'}), 400
    total = sum(item.price * item.quantity for item in cart)
    if current_user.balance < total:
        return jsonify({'error': 'Insufficient balance'}), 400
    order = Order(user_id=current_user.id)
    db.session.add(order)
    for item in cart:
        db.session.add(OrderItem(name=item.name, price=item.price * item.quantity, order=order))
        db.session.delete(item)
    current_user.balance -= total
    db.session.commit()
    return jsonify({'message': 'Order placed', 'balance': current_user.balance})

@app.route('/api/orders')
@token_required
def get_orders(current_user):
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return jsonify({
        'username': current_user.username,
        'balance': current_user.balance,
        'joinDate': current_user.join_date,
        'orders': [{
            'id': order.id,
            'items': [{
                'name': item.name,
                'price': item.price
            } for item in order.items]
        } for order in orders]
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
