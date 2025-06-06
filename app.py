from flask import Flask, request, jsonify, make_response, redirect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os

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
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    orders = db.relationship('Order', backref='user', lazy=True)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(120), nullable=False)
    price = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Utility decorator to require login via JWT cookie
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired!'}), 401
        except Exception:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Routes

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'message': 'Username and password required.'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists.'}), 409

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully.'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid username or password.'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    resp = make_response(jsonify({'message': 'Logged in successfully.'}))
    resp.set_cookie('token', token, httponly=True, samesite='Lax')  # add secure=True if HTTPS
    return resp

@app.route('/logout', methods=['POST'])
def logout():
    resp = make_response(jsonify({'message': 'Logged out successfully.'}))
    resp.set_cookie('token', '', expires=0)
    return resp

@app.route('/profile')
@token_required
def profile(current_user):
    orders = [{'id': o.id, 'item_name': o.item_name, 'price': o.price, 'created_at': o.created_at.isoformat()} for o in current_user.orders]
    return jsonify({
        'username': current_user.username,
        'balance': current_user.balance,
        'join_date': current_user.created_at.isoformat(),
        'orders': orders
    })

@app.route('/balance', methods=['GET', 'POST'])
@token_required
def balance(current_user):
    if request.method == 'GET':
        return jsonify({'balance': current_user.balance})
    elif request.method == 'POST':
        data = request.get_json()
        amount = data.get('amount')
        if amount is None or not isinstance(amount, (int, float)) or amount < 0:
            return jsonify({'message': 'Invalid amount'}), 400
        current_user.balance += float(amount)
        db.session.commit()
        return jsonify({'balance': current_user.balance})

@app.route('/orders', methods=['GET', 'POST'])
@token_required
def orders(current_user):
    if request.method == 'GET':
        orders = [{'id': o.id, 'item_name': o.item_name, 'price': o.price, 'created_at': o.created_at.isoformat()} for o in current_user.orders]
        return jsonify({'orders': orders})
    elif request.method == 'POST':
        data = request.get_json()
        item_name = data.get('item_name')
        price = data.get('price')
        if not item_name or not isinstance(price, (int, float)) or price <= 0:
            return jsonify({'message': 'Invalid order data'}), 400
        if current_user.balance < price:
            return jsonify({'message': 'Insufficient balance'}), 400
        current_user.balance -= price
        new_order = Order(item_name=item_name, price=price, user=current_user)
        db.session.add(new_order)
        db.session.commit()
        return jsonify({'message': 'Order placed successfully.'})

@app.route('/')
def index():
    token = request.cookies.get('token')
    if token:
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            return redirect('/home')
        except Exception:
            pass
    return redirect('/login')

@app.route('/home')
@token_required
def home(current_user):
    return jsonify({'message': f'Welcome, {current_user.username}! Your balance is ${current_user.balance:.2f}.'})

# Initialize DB (run once on first request)
@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
