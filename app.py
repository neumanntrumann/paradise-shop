from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_super_secret_key_here'  # Change this to something secret!

# In-memory "database" for demo
users_db = {}  # key: username, value: dict with password hash, balance, orders, join date, cart, etc.

# Helper to check if user logged in
def is_logged_in():
    return 'username' in session

@app.route('/')
def index():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({'error': 'Missing username or password'}), 400

        user = users_db.get(username)
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            return jsonify({'message': 'Login successful'}), 200
        else:
            return jsonify({'error': 'Invalid username or password'}), 401

    # GET request serves login page
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Missing username or password'}), 400

        if username in users_db:
            return jsonify({'error': 'Username already exists'}), 400

        password_hash = generate_password_hash(password)
        users_db[username] = {
            'password_hash': password_hash,
            'balance': 100.0,  # Starting balance for demo
            'orders': [],
            'join_date': datetime.now().strftime('%Y-%m-%d'),
            'cart': []
        }
        session['username'] = username
        return jsonify({'message': 'Signup successful'}), 201

    # GET request serves signup page
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/balance')
def balance():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('balance.html')

@app.route('/marketplace')
def marketplace():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('marketplace.html')

@app.route('/cart')
def cart():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('cart.html')

@app.route('/checkout')
def checkout():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('checkout.html')

@app.route('/orders')
def orders():
    if not is_logged_in():
        return redirect(url_for('login'))
    return render_template('orders.html')

# API route to fetch user data including orders, balance, etc.
@app.route('/api/userdata')
def userdata():
    if not is_logged_in():
        return jsonify({'error': 'Unauthorized'}), 401

    username = session['username']
    user = users_db.get(username)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Return user data
    return jsonify({
        'username': username,
        'balance': user['balance'],
        'orders': user['orders'],
        'joinDate': user['join_date'],
        'cart': user['cart']
    })

# Example API: Add item to cart
@app.route('/api/cart/add', methods=['POST'])
def add_to_cart():
    if not is_logged_in():
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    item = data.get('item')
    if not item or not isinstance(item, dict):
        return jsonify({'error': 'Invalid item data'}), 400

    username = session['username']
    users_db[username]['cart'].append(item)
    return jsonify({'message': 'Item added to cart'}), 200

# Example API: Place an order (checkout)
@app.route('/api/checkout', methods=['POST'])
def checkout_api():
    if not is_logged_in():
        return jsonify({'error': 'Unauthorized'}), 401

    username = session['username']
    user = users_db[username]

    if len(user['cart']) == 0:
        return jsonify({'error': 'Cart is empty'}), 400

    total_price = sum(item.get('price', 0) for item in user['cart'])
    if user['balance'] < total_price:
        return jsonify({'error': 'Insufficient balance'}), 400

    # Deduct balance
    user['balance'] -= total_price

    # Add cart as new order
    user['orders'].append(user['cart'].copy())

    # Clear cart
    user['cart'].clear()

    return jsonify({'message': 'Order placed successfully', 'balance': user['balance']}), 200

if __name__ == '__main__':
    app.run(debug=True)
