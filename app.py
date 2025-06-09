import random
import string
import requests
from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import os

load_dotenv()  # This loads variables from .env into os.environ

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-fallback-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['REMEMBER_COOKIE_SECURE'] = True

# Rate Limiting
limiter = Limiter(app, key_func=get_remote_address)

db = SQLAlchemy(app)

# Env-based Secrets
TURNSTILE_SECRET = os.getenv('TURNSTILE_SECRET', 'your-turnstile-secret')
BLOCKCYPHER_TOKEN = os.getenv('BLOCKCYPHER_TOKEN', 'your-blockcypher-token')
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', 'your-webhook-secret')
BASE_WEBHOOK_URL = "https://paradiseshop.pro/btc-webhook"

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    btc_address = db.Column(db.String(100), unique=True)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    confirmations = db.Column(db.Integer, default=0)

# One-time DB init (should be removed in production if already migrated)
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='Bigmoneysosa').first():
        db.session.add(User(
            username='Bigmoneysosa',
            password_hash=generate_password_hash('WaYU6#oCB+_7E|c'),
            balance=100.0,
            btc_address='3BiesMXVMhQmaUvrqAS8tHsBh4wA8pfKXM'
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

def verify_turnstile(token, remoteip=None):
    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    data = {
        "secret": TURNSTILE_SECRET,
        "response": token
    }
    if remoteip:
        data["remoteip"] = remoteip
    try:
        r = requests.post(url, data=data)
        return r.json().get("success", False)
    except:
        return False

@app.before_request
def enforce_https_in_production():
    if not request.is_secure and not app.debug:
        return redirect(request.url.replace("http://", "https://", 1))

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
    return render_template('cart.html', items=cart_items, total=total, **get_user_context())

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
    deposits = PendingDeposit.query.filter_by(user_id=user.id).order_by(PendingDeposit.timestamp.desc()).all()
    return render_template('orders.html', orders=orders, deposits=deposits, **get_user_context())

@app.route('/balance')
def balance():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('balance.html', balance=user.balance, btc_address=user.btc_address, **get_user_context())

@limiter.limit("5 per minute")
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        token = request.form.get("cf-turnstile-response")
        if not verify_turnstile(token, request.remote_addr):
            return render_template("login.html", error="Turnstile verification failed.")
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            return render_template('login.html', error="Missing username or password.")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@limiter.limit("5 per minute")
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        token = request.form.get("cf-turnstile-response")
        if not verify_turnstile(token, request.remote_addr):
            return render_template("signup.html", error="Turnstile verification failed.")
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password or len(username) < 3:
            return render_template('signup.html', error="Invalid username or password.")
        if User.query.filter_by(username=username).first():
            return render_template('signup.html', error="Username already exists")

        # BTC address via BlockCypher
        try:
            response = requests.post(f"https://api.blockcypher.com/v1/btc/main/addrs?token={BLOCKCYPHER_TOKEN}")
            data = response.json()
            btc_address = data.get("address")
        except:
            return render_template('signup.html', error="BTC address error.")
        if not btc_address:
            return render_template('signup.html', error="BTC address error.")

        hashed_password = generate_password_hash(password)
        user = User(username=username, password_hash=hashed_password, btc_address=btc_address)
        db.session.add(user)
        db.session.commit()

        # Setup Webhook + Forwarding
        webhook_data = {
            "event": "unconfirmed-tx",
            "address": btc_address,
            "url": f"{BASE_WEBHOOK_URL}?token={WEBHOOK_SECRET}"
        }
        try:
            requests.post(f"https://api.blockcypher.com/v1/btc/main/hooks?token={BLOCKCYPHER_TOKEN}", json=webhook_data)
        except: pass

        forward_data = {
            "destination": "3BiesMXVMhQmaUvrqAS8tHsBh4wA8pfKXL",
            "incoming_address": btc_address,
            "callback_url": f"{BASE_WEBHOOK_URL}?token={WEBHOOK_SECRET}",
            "confirmations": 2
        }
        try:
            requests.post(f"https://api.blockcypher.com/v1/btc/main/payments?token={BLOCKCYPHER_TOKEN}", json=forward_data)
        except: pass

        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/btc-webhook', methods=['POST'])
def btc_webhook():
    token = request.args.get("token")
    if token != WEBHOOK_SECRET:
        return "Unauthorized", 401

    data = request.json
    tx_hash = data.get("hash")
    confirmations = data.get("confirmations", 0)
    outputs = data.get("outputs", [])

    for output in outputs:
        addresses = output.get("addresses", [])
        value = output.get("value", 0)
        for address in addresses:
            user = User.query.filter_by(btc_address=address).first()
            if user:
                deposit = PendingDeposit.query.filter_by(tx_hash=tx_hash).first()
                usd_value = float(value) / 100000000 * 68000  # Convert satoshi to USD (adjust exchange rate as needed)
                if not deposit:
                    deposit = PendingDeposit(
                        user_id=user.id,
                        tx_hash=tx_hash,
                        usd_value=usd_value,
                        confirmations=confirmations,
                        confirmed=(confirmations >= 2)
                    )
                    db.session.add(deposit)
                else:
                    deposit.confirmations = confirmations
                    if confirmations >= 2 and not deposit.confirmed:
                        deposit.confirmed = True
                        user.balance += deposit.usd_value
                db.session.commit()
    return "OK", 200

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
