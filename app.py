from flask import Flask, render_template, request, redirect, url_for, session, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY', 'your_super_secret_key_here')

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False  # Set True in production with HTTPS!
)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ------------------- DATABASE MODELS ------------------- #

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    balance = db.Column(db.Float, default=100.0)
    join_date = db.Column(db.String(20), default=lambda: datetime.now().strftime('%Y-%m-%d'))
    
    cart_items = db.relationship('CartItem', backref='user', lazy=True, cascade="all, delete-orphan")
    orders = db.relationship('Order', backref='user', lazy=True, cascade="all, delete-orphan")

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
    order_date = db.Column(db.String(20), default=lambda: datetime.now().strftime('%Y-%m-%d'))
    total_price = db.Column(db.Float, nullable=False)
    order_items = db.relationship('OrderItem', backref='order', lazy=True, cascade="all, delete-orphan")

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('marketplace_item.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)
    price_at_purchase = db.Column(db.Float, nullable=False)
    
    item = db.relationship('MarketplaceItem')

# ------------------- HELPER FUNCTIONS ------------------- #

@app.before_request
def load_user():
    g.user = None
    username = session.get('username')
    if username:
        user = User.query.filter_by(username=username).first()
        if user:
            g.user = user
        else:
            session.clear()

def login_required_redirect():
    if not g.user:
        return redirect(url_for('login'))

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
            }
            for oi in order.order_items
        ]
    }

# ------------------- ROUTES ------------------- #

@app.route('/')
def index():
    if not g.user:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')

        if not username or not password:
            return jsonify({'error': 'Missing username or password'}), 400

        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400

        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        session['username'] = username
        return jsonify({'message': 'Signup successful'}), 201

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({'error': 'Invalid username or password'}), 401

        session['username'] = username
        return jsonify({'message': 'Login successful'}), 200

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/balance')
def balance():
    if not g.user:
        return redirect(url_for('login'))
    return render_template('balance.html')

@app.route('/marketplace')
def marketplace():
    if not g.user:
        return redirect(url_for('login'))
    
    items = MarketplaceItem.query.all()
    return render_template('marketplace.html', items=items)

@app.route('/cart')
def cart():
    if not g.user:
        return redirect(url_for('login'))

    cart_items = g.user.cart_items
    return render_template('cart.html', cart_items=cart_items)

@app.route('/checkout')
def checkout():
    if not g.user:
        return redirect(url_for('login'))
    return render_template('checkout.html')

@app.route('/orders')
def orders():
    if not g.user:
        return redirect(url_for('login'))

    user_orders = g.user.orders
    return render_template('orders.html', orders=user_orders)

# ------------------- API ENDPOINTS ------------------- #

@app.route('/api/userdata')
def userdata():
    if not g.user:
        return jsonify({'error': 'Unauthorized'}), 401

    return jsonify({
        'username': g.user.username,
        'balance': g.user.balance,
        'joinDate': g.user.join_date,
        'cart': [serialize_cart_item(ci) for ci in g.user.cart_items],
        'orders': [serialize_order(o) for o in g.user.orders]
    })

@app.route('/api/cart/add', methods=['POST'])
def add_to_cart():
    if not g.user:
        return jsonify({'error': 'Unauthorized'}), 401

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
def remove_from_cart(item_id):
    if not g.user:
        return jsonify({'error': 'Unauthorized'}), 401

    cart_item = CartItem.query.filter_by(user_id=g.user.id, item_id=item_id).first()
    if not cart_item:
        return jsonify({'error': 'Item not found in cart'}), 404

    db.session.delete(cart_item)
    db.session.commit()

    return jsonify({'message': 'Item removed from cart'}), 200

@app.route('/api/checkout', methods=['POST'])
def checkout_api():
    if not g.user:
        return jsonify({'error': 'Unauthorized'}), 401

    cart_items = g.user.cart_items
    if not cart_items:
        return jsonify({'error': 'Cart is empty'}), 400

    total_price = sum(ci.quantity * ci.item.price for ci in cart_items)
    if g.user.balance < total_price:
        return jsonify({'error': 'Insufficient balance'}), 400

    # Create new order
    order = Order(user_id=g.user.id, total_price=total_price)
    db.session.add(order)
    db.session.flush()  # To get order.id before commit

    for ci in cart_items:
        order_item = OrderItem(
            order_id=order.id,
            item_id=ci.item.id,
            quantity=ci.quantity,
            price_at_purchase=ci.item.price
        )
        db.session.add(order_item)

    # Deduct balance and clear cart
    g.user.balance -= total_price
    CartItem.query.filter_by(user_id=g.user.id).delete(synchronize_session=False)

    db.session.commit()

    return jsonify({'message': 'Order placed successfully', 'balance': g.user.balance}), 200


# ------------------- INITIAL DATA LOAD ------------------- #

def load_sample_marketplace_items():
    if MarketplaceItem.query.first():
        return

    sample_items = [
        {'name': 'Tropical Shirt', 'price': 25.99, 'description': 'Light and breezy shirt', 'image': '/static/img/shirt1.jpg'},
        {'name': 'Beach Hat', 'price': 15.50, 'description': 'Protect yourself from sun', 'image': '/static/img/hat1.jpg'},
        {'name': 'Sunglasses', 'price': 45.00, 'description': 'Stylish shades for sunny days', 'image': '/static/img/sunglasses1.jpg'},
    ]

    for item in sample_items:
        new_item = MarketplaceItem(**item)
        db.session.add(new_item)
    db.session.commit()

# ------------------- MAIN ------------------- #

if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists('users.db'):
            db.create_all()
            load_sample_marketplace_items()

    app.run(debug=True)
