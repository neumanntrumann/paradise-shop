import random
import string
import requests
from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'secret123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# BlockCypher configuration
BLOCKCYPHER_TOKEN = 'dbd5a9f9a6b5403a8c0171bd25b5e883'
WEBHOOK_SECRET = '55f66a40b826bd9cfa3f2b70d958ae6c'
BASE_WEBHOOK_URL = "https://paradiseshop.pro/btc-webhook"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    btc_address = db.Column(db.String(100), unique=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer, default=1)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_name = db.Column(db.String(100))
    hash_string = db.Column(db.String(10))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class PendingDeposit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tx_hash = db.Column(db.String(100), unique=True)
    usd_value = db.Column(db.Float)
    confirmed = db.Column(db.Boolean, default=False)

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        db.session.add(User(
            username='Bigmoneysosa',
            password='Blackcherry7!',
            balance=100.0,
            btc_address='3BiesMXVMhQmaUvrqAS8tHsBh4wA8pfKXL'
        ))
    if not Product.query.first():
        db.session.add_all([
            Product(name='Spammed CC', price=15.00, description='90% Validity Restocked Fresh Everyday'),
            Product(name='X2 EMV Software', price=400.00, description='Everything you need to know about EMV software...'),
            Product(name='Spamming Bundle', price=500.00, description='Includes email spammer, phishing templates, spoofing tools, SMS spammer, bypass tools, and tutorials.'),
            Product(name='D+P Pack', price=150.00, description='Real fresh checked d+p 💳100% valid been selling since 2020 check my vouches 5 years worth✅201 code only👨‍💻'),
            Product(name='Your Own Shop Website', price=1000.00, description='Custom shop created just like this one to your taste and style with instructions.'),
            Product(name='Money Order Method with Tutorial', price=250.00, description='Includes money order tutorial with everything you need.'),
            Product(name='Check Bundle', price=500.00, description='Includes everything needed to make checks, full tutorial with all the templates.')
        ])
    db.session.commit()

def get_user_context():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        order_count = Order.query.filter_by(user_id=user.id).count()
        return {'user': user, 'order_count': order_count}
    return {'user': None, 'order_count': 0}

@app.route('/')
@app.route('/index')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', **get_user_context())

@app.route('/marketplace')
def marketplace():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    products = Product.query.all()
    return render_template('marketplace.html', products=products, **get_user_context())

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    existing = CartItem.query.filter_by(user_id=session['user_id'], product_id=product_id).first()
    if existing:
        existing.quantity += 1
    else:
        db.session.add(CartItem(user_id=session['user_id'], product_id=product_id, quantity=1))
    db.session.commit()
    return redirect(url_for('marketplace'))

@app.route('/remove_from_cart/<int:cart_id>', methods=['POST'])
def remove_from_cart(cart_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    item = CartItem.query.get(cart_id)
    if item and item.user_id == session['user_id']:
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    items = CartItem.query.filter_by(user_id=session['user_id']).all()
    cart_items = []
    total = 0
    for item in items:
        product = Product.query.get(item.product_id)
        subtotal = product.price * item.quantity
        total += subtotal
        cart_items.append({'product': product, 'quantity': item.quantity, 'id': item.id})
    context = get_user_context()
    return render_template('cart.html', items=cart_items, total=total, **context)

@app.route('/checkout', methods=['POST'])
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    items = CartItem.query.filter_by(user_id=session['user_id']).all()
    user = User.query.get(session['user_id'])
    total = sum(Product.query.get(item.product_id).price * item.quantity for item in items)
    if user.balance < total:
        return "Insufficient balance."
    for item in items:
        product = Product.query.get(item.product_id)
        for _ in range(item.quantity):
            hash_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
            db.session.add(Order(user_id=user.id, product_name=product.name, hash_string=hash_str))
    user.balance -= total
    CartItem.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    return redirect(url_for('orders'))

@app.route('/orders', methods=['GET', 'POST'])
def orders():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    orders = Order.query.filter_by(user_id=user.id).order_by(Order.timestamp.desc()).all()
    if request.method == 'POST' and user.username == 'admin':
        hash_code = request.form.get('hash_code', '').strip()
        order = Order.query.filter_by(hash_string=hash_code).first()
        if order:
            owner = User.query.get(order.user_id)
            flash(f"✔️ VALID: {order.product_name} by {owner.username} at {order.timestamp.strftime('%Y-%m-%d %H:%M:%S')}", 'success')
        else:
            flash("❌ INVALID or unknown hash.", 'error')
    return render_template('orders.html', orders=orders, **get_user_context())

@app.route('/balance')
def balance():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('balance.html', balance=user.balance, btc_address=user.btc_address, **get_user_context())

@app.route('/more')
def more():
    return render_template('more.html', **get_user_context())

@app.route('/btc-webhook', methods=['POST'])
def btc_webhook():
    token = request.args.get("token")
    if token != WEBHOOK_SECRET:
        return "Unauthorized", 401
    data = request.json
    tx_hash = data.get("hash")
    confirmations = data.get("confirmations", 0)
    outputs = data.get("outputs", [])
    if confirmations >= 2:
        for output in outputs:
            addresses = output.get("addresses", [])
            value = output.get("value", 0)
            for address in addresses:
                user = User.query.filter_by(btc_address=address).first()
                if user and not PendingDeposit.query.filter_by(tx_hash=tx_hash).first():
                    usd_value = float(value) / 100000000 * 68000
                    deposit = PendingDeposit(user_id=user.id, tx_hash=tx_hash, usd_value=usd_value, confirmed=True)
                    user.balance += usd_value
                    db.session.add(deposit)
                    db.session.commit()
                    flash("✅ Deposit confirmed and balance updated.", "success")
    return "OK", 200

@app.route('/profile-data')
def profile_data():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    user = User.query.get(session['user_id'])
    order_count = Order.query.filter_by(user_id=user.id).count()
    return jsonify({
        'username': user.username,
        'balance': round(user.balance, 2),
        'order_count': order_count
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if User.query.filter_by(username=username).first():
            return render_template('signup.html', error="Username already exists")
        api_url = f"https://api.blockcypher.com/v1/btc/main/addrs?token={BLOCKCYPHER_TOKEN}"
        try:
            response = requests.post(api_url)
            data = response.json()
            btc_address = data.get("address")
        except:
            return render_template('signup.html', error="BTC address error.")
        if not btc_address:
            return render_template('signup.html', error="BTC address error.")
        user = User(username=username, password=password, btc_address=btc_address)
        db.session.add(user)
        db.session.commit()

        webhook_url = f"https://api.blockcypher.com/v1/btc/main/hooks?token={BLOCKCYPHER_TOKEN}"
        webhook_data = {
            "event": "unconfirmed-tx",
            "address": btc_address,
            "url": f"{BASE_WEBHOOK_URL}?token={WEBHOOK_SECRET}"
        }
        try:
            requests.post(webhook_url, json=webhook_data)
        except:
            pass

        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/verify', methods=['GET', 'POST'])
def verify_order():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if user.username != 'admin':
        return redirect(url_for('index'))
    result = None
    if request.method == 'POST':
        hash_input = request.form.get('hash_input')
        order = Order.query.filter_by(hash_string=hash_input).first()
        if order:
            owner = User.query.get(order.user_id)
            result = {
                'valid': True,
                'username': owner.username,
                'product_name': order.product_name,
                'timestamp': order.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            }
        else:
            result = {'valid': False}
    return render_template('verify.html', result=result, **get_user_context())

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
