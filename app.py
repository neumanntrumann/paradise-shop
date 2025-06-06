from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import functools
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///paradise_shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    join_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    orders = db.relationship('Order', backref='user', lazy=True)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    items = db.Column(db.Text, nullable=False)  # Store JSON string
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# JWT auth decorator
def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('jwt')
        if not token:
            return redirect(url_for('login'))
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except:
            return redirect(url_for('login'))
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/')
@token_required
def index(current_user):
    return render_template('index.html')

@app.route('/marketplace')
@token_required
def marketplace(current_user):
    return render_template('marketplace.html')

@app.route('/orders')
@token_required
def orders(current_user):
    order_list = Order.query.filter_by(user_id=current_user.id).all()
    orders = []
    for order in order_list:
        items = eval(order.items)
        orders.append({
            'id': order.id,
            'items': items,
            'timestamp': order.timestamp
        })
    return jsonify({
        'username': current_user.username,
        'balance': current_user.balance,
        'joinDate': current_user.join_date.strftime('%Y-%m-%d'),
        'orders': orders
    })

@app.route('/cart')
@token_required
def cart(current_user):
    return render_template('cart.html')

@app.route('/balance')
@token_required
def balance(current_user):
    return render_template('balance.html')

@app.route('/more')
@token_required
def more(current_user):
    return '<h1>More page coming soon.</h1>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            resp = make_response(redirect(url_for('index')))
            resp.set_cookie('jwt', token, httponly=True)
            return resp
        return 'Invalid credentials', 401
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        if User.query.filter_by(username=username).first():
            return 'User already exists', 409
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('jwt')
    return resp

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
