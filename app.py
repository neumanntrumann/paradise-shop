
from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    balance = db.Column(db.Float, default=50.0)  # start with balance
    orders = db.relationship('Order', backref='user', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

def create_tables_and_seed():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        db.session.add(User(username='admin', password='admin', balance=100.0))
    if not Product.query.first():
        db.session.add_all([
            Product(name='Island Coconut Lip Balm', price=5.99),
            Product(name='Tropical Body Butter', price=12.49),
            Product(name='Beach Vibes Scented Candle', price=9.99)
        ])
    db.session.commit()

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/balance')
def balance():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('balance.html', balance=user.balance)

@app.route('/orders')
def orders():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_orders = Order.query.filter_by(user_id=session['user_id']).all()
    return render_template('orders.html', orders=user_orders)

@app.route('/checkout/<int:product_id>')
def checkout(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    product = Product.query.get(product_id)
    if user.balance >= product.price:
        user.balance -= product.price
        order = Order(user_id=user.id, product_id=product.id)
        db.session.add(order)
        db.session.commit()
        flash('Purchase successful!')
    else:
        flash('Not enough balance.')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

create_tables_and_seed()

if __name__ == '__main__':
    app.run(debug=True)
