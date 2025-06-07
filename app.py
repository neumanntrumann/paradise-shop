
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_jwt_secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    balance = db.Column(db.Float, default=50.0)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    product_id = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400
    hashed_pw = generate_password_hash(data['password'], method='sha256')
    user = User(username=data['username'], password_hash=hashed_pw)
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'Signup successful'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if not user or not user.verify_password(data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=12)}, app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({'token': token})

@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        'username': current_user.username,
        'balance': current_user.balance
    })

@app.route('/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([{'id': p.id, 'name': p.name, 'price': p.price} for p in products])

@app.route('/checkout/<int:product_id>', methods=['POST'])
@token_required
def checkout(current_user, product_id):
    product = Product.query.get(product_id)
    if not product or current_user.balance < product.price:
        return jsonify({'message': 'Not enough balance'}), 400
    current_user.balance -= product.price
    order = Order(user_id=current_user.id, product_id=product.id)
    db.session.add(order)
    db.session.commit()
    return jsonify({'message': 'Purchase successful'})

@app.route('/orders', methods=['GET'])
@token_required
def get_orders(current_user):
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return jsonify([{'order_id': o.id, 'product_id': o.product_id, 'timestamp': o.timestamp} for o in orders])

@app.route('/balance', methods=['GET'])
@token_required
def get_balance(current_user):
    return jsonify({'balance': current_user.balance})

@app.route('/')
def serve_index():
    return send_from_directory('templates', 'index.html')

def seed():
    with app.app_context():
        db.create_all()
        if not Product.query.first():
            db.session.add_all([
                Product(name='Coconut Lip Balm', price=5.99),
                Product(name='Tropical Butter', price=12.49),
                Product(name='Beach Candle', price=9.99)
            ])
        db.session.commit()

seed()

if __name__ == '__main__':
    app.run(debug=True)
