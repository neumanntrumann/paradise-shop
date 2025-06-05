from flask import Flask, render_template, request, jsonify, redirect, url_for, g, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt
import datetime

app = Flask(__name__)

# Configs
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', '6LeaIlYrAAAAAKMvAK061JHTnGXTXx7Hagh-NMJh')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///paradise_shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# -------------------- MODELS -------------------- #

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    balance = db.Column(db.Float, default=100.0)
    join_date = db.Column(db.String(20), default=lambda: datetime.datetime.now().strftime('%Y-%m-%d'))

    cart_items = db.relationship('CartItem', backref='user', lazy=True, cascade="all, delete-orphan")
    orders = db.relationship('Order', backref='user', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class MarketplaceItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    image = db.Column(db.String(200))

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('marketplace_item.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)
    item = db.relationship('MarketplaceItem')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    order_date = db.Column(db.String(20), default=lambda: datetime.datetime.now().strftime('%Y-%m-%d'))
    total_price = db.Column(db.Float, nullable=False)
    order_items = db.relationship('OrderItem', backref='order', lazy=True, cascade="all, delete-orphan")

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('marketplace_item.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)
    price_at_purchase = db.Column(db.Float, nullable=False)
    item = db.relationship('MarketplaceItem')

# -------------------- HELPERS -------------------- #

def generate_jwt(user_id, username):
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=8)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

def decode_jwt(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

@app.before_request
def load_user():
    g.user = None
    token = request.cookies.get('access_token')
    print("Token from cookie:", token)  # Debug print
    if token:
        payload = decode_jwt(token)
        print("Decoded payload:", payload)  # Debug print
        if payload:
            user = User.query.filter_by(id=payload.get('user_id')).first()
            print("User from DB:", user)  # Debug print
            if user:
                g.user = user

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def serialize_item(item):
    return {
        'id': item.id,
        'name': item.name,
        'price': item.price,
        'description': item.description,
        'image': item.image
    }

def serialize_cart_item(cart_item):
    return {
        'id': cart_item.item.id,
        'name': cart_item.item.name,
        'price': cart_item.item.price,
        'description': cart_item.item.description,
        'image': cart_item.item.image,
        'quantity': cart_item.quantity
    }

def serialize_order(order):
    return {
        'id': order.id,
        'order_date': order.order_date,
        'total_price': order.total_price,
        'items': [
            {
                'id': oi.item.id,
                'name': oi.item.name,
                'quantity': oi.quantity,
                'price_at_purchase': oi.price_at_purchase
            } for oi in order.order_items
        ]
    }

# -------------------- ROUTES -------------------- #

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password required.'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Username already exists.'}), 409

    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully.'}), 201

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() if request.is_json else request.form
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return render_template('login.html', error='Username and password are required'), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return render_template('login.html', error='Invalid username or password'), 401

    token = generate_jwt(user.id, user.username)
    response = redirect(url_for('index'))
    response.set_cookie('access_token', token, httponly=True, samesite='Lax', max_age=8*3600, path='/')
    return response

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login_page')))
    response.set_cookie('access_token', '', expires=0, path='/')
    return response

@app.route('/balance')
@login_required
def balance():
    return render_template('balance.html')

@app.route('/marketplace')
@login_required
def marketplace():
    items = MarketplaceItem.query.all()
    return render_template('marketplace.html', items=items)

@app.route('/cart')
@login_required
def cart():
    cart_items = g.user.cart_items
    return render_template('cart.html', cart_items=cart_items)

@app.route('/checkout')
@login_required
def checkout():
    return render_template('checkout.html')

@app.route('/orders')
@login_required
def orders():
    user_orders = g.user.orders
    return render_template('orders.html', orders=user_orders)

# -------------------- API ENDPOINTS -------------------- #

@app.route('/api/userdata')
@login_required
def userdata():
    return jsonify({
        'username': g.user.username,
        'balance': g.user.balance,
        'joinDate': g.user.join_date,
        'cart': [serialize_cart_item(ci) for ci in g.user.cart_items],
        'orders': [serialize_order(o) for o in g.user.orders]
    })

@app.route('/api/cart/add', methods=['POST'])
@login_required
def add_to_cart():
    if not request.is_json:
        return jsonify({'error': 'Expected JSON data'}), 400
    data = request.get_json()
    item_id = data.get('item_id')
    quantity = data.get('quantity', 1)

    if not isinstance(item_id, int) or not isinstance(quantity, int) or quantity < 1:
        return jsonify({'error': 'Invalid item_id or quantity'}), 400

    item = MarketplaceItem.query.get(item_id)
    if not item:
        return jsonify({'error': 'Item not found'}), 404

    cart_item = CartItem.query.filter_by(user_id=g.user.id, item_id=item.id).first()
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = CartItem(user_id=g.user.id, item_id=item.id, quantity=quantity)
        db.session.add(cart_item)
    db.session.commit()

    return jsonify({'message': f"Added {quantity} x '{item.name}' to cart"}), 200

@app.route('/api/cart/item/<int:item_id>', methods=['DELETE'])
@login_required
def remove_from_cart(item_id):
    cart_item = CartItem.query.filter_by(user_id=g.user.id, item_id=item_id).first()
    if not cart_item:
        return jsonify({'error': 'Item not found in cart'}), 404

    db.session.delete(cart_item)
    db.session.commit()
    return jsonify({'message': 'Item removed from cart'}), 200

@app.route('/api/checkout', methods=['POST'])
@login_required
def checkout_api():
    cart_items = g.user.cart_items
    if not cart_items:
        return jsonify({'error': 'Cart is empty'}), 400

    total_price = sum(ci.quantity * ci.item.price for ci in cart_items)
    if g.user.balance < total_price:
        return jsonify({'error': 'Insufficient balance'}), 400

    order = Order(user_id=g.user.id, total_price=total_price)
    db.session.add(order)
    db.session.flush()

    for ci in cart_items:
        order_item = OrderItem(
            order_id=order.id,
            item_id=ci.item.id,
            quantity=ci.quantity,
            price_at_purchase=ci.item.price
        )
        db.session.add(order_item)

    g.user.balance -= total_price
    CartItem.query.filter_by(user_id=g.user.id).delete(synchronize_session=False)
    db.session.commit()

    return jsonify({'message': 'Order placed successfully', 'balance': g.user.balance}), 200

# -------------------- INITIAL DATA LOAD -------------------- #

def load_sample_marketplace_items():
    if MarketplaceItem.query.first():
        return

    sample_items = [
        {'name': 'Tropical Shirt', 'price': 25.99, 'description': 'Light and breezy shirt', 'image': '/static/img/shirt1.jpg'},
        {'name': 'Beach Hat', 'price': 15.50, 'description': 'Protect yourself from sun', 'image': '/static/img/hat1.jpg'},
        {'name': 'Sunglasses', 'price': 45.00, 'description': 'Stylish shades for sunny days', 'image': '/static/img/sunglasses1.jpg'},
    ]

    for item in sample_items:
        db.session.add(MarketplaceItem(**item))
    db.session.commit()

# -------------------- MAIN -------------------- #

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        load_sample_marketplace_items()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
