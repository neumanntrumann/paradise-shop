import random
import string
import requests
from flask import Flask, render_template, request, redirect, session, url_for
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
BTC_ADDRESS = 'YOUR_BTC_WALLET_ADDRESS_HERE'  # Replace with actual BTC address
WEBHOOK_SECRET = '55f66a40b826bd9cfa3f2b70d958ae6c'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    balance = db.Column(db.Float, default=100.0)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)

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
        db.session.add(User(username='admin', password='admin', balance=100.0))
    if not Product.query.first():
        db.session.add_all([
            Product(name='Spammed CC', price=15.00),
            Product(name='X2 EMV Software', price=400.00),
            Product(name='Spamming Bundle', price=500.00),
            Product(name='D+P Pack', price=150.00)
        ])
    db.session.commit()

@app.route('/')
@app.route('/index')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/marketplace')
def marketplace():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    products = Product.query.all()
    return render_template('marketplace.html', products=products)

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
        cart_items.append({'product': product, 'quantity': item.quantity})
    return render_template('cart.html', items=cart_items, total=total)

@app.route('/checkout')
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    items = CartItem.query.filter_by(user_id=session['user_id']).all()
    user = User.query.get(session['user_id'])
    total = 0
    for item in items:
        product = Product.query.get(item.product_id)
        total += product.price * item.quantity

    if user.balance < total:
        return "Insufficient balance."

    for item in items:
        product = Product.query.get(item.product_id)
        for _ in range(item.quantity):
            hash_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
            db.session.add(Order(user_id=user.id, product_name=product.name, hash_string=hash_str))

    user.balance -= total
    CartItem.query.filter_by(user_id=session['user_id']).delete()
    db.session.commit()
    return redirect(url_for('orders'))

@app.route('/orders')
def orders():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    orders = Order.query.filter_by(user_id=session['user_id']).order_by(Order.timestamp.desc()).all()
    return render_template('orders.html', orders=orders)

@app.route('/balance')
def balance():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('balance.html', balance=user.balance, btc_address=BTC_ADDRESS)

@app.route('/more')
def more():
    return render_template('more.html')

@app.route('/btc-webhook', methods=['POST'])
def btc_webhook():
    data = request.json
    if data.get("token") != WEBHOOK_SECRET:
        return "Unauthorized", 401

    tx_hash = data.get("hash")
    confirmations = data.get("confirmations", 0)
    outputs = data.get("outputs", [])

    if confirmations >= 2:
        for output in outputs:
            if output["addresses"] and BTC_ADDRESS in output["addresses"]:
                usd_value = float(output["value"]) / 100000000 * 68000  # convert satoshi to USD (approx)
                deposit = PendingDeposit.query.filter_by(tx_hash=tx_hash).first()
                if not deposit:
                    user = User.query.filter_by(username="admin").first()
                    deposit = PendingDeposit(user_id=user.id, tx_hash=tx_hash, usd_value=usd_value, confirmed=True)
                    user.balance += usd_value
                    db.session.add(deposit)
                    db.session.commit()
    return "OK", 200

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
        db.session.add(User(username=username, password=password))
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
