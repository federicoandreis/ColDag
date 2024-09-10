from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Project
from config import Config
import os
import json
from io import BytesIO
import networkx as nx

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_default_user():
    username = 'fede'
    password = 'admin'
    if not User.query.filter_by(username=username).first():
        new_user = User(username=username, email='fede@example.com', password=generate_password_hash(password), is_admin=True)
        db.session.add(new_user)
        db.session.commit()
        print(f"Default user '{username}' created.")
    else:
        print(f"Default user '{username}' already exists.")

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        is_admin = request.form.get('is_admin') == 'on'
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
        elif User.query.filter_by(email=email).first():
            flash('Email already exists')
        else:
            new_user = User(username=username, email=email, password=generate_password_hash(password),
                            first_name=first_name, last_name=last_name, is_admin=is_admin)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.first_name = request.form.get('first_name')
        current_user.last_name = request.form.get('last_name')
        current_user.email = request.form.get('email')
        db.session.commit()
        flash('Profile updated successfully')
    return render_template('profile.html')

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not check_password_hash(current_user.password, current_password):
        flash('Current password is incorrect')
    elif new_password != confirm_password:
        flash('New passwords do not match')
    else:
        current_user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Password changed successfully')
    return redirect(url_for('profile'))

# ... (rest of the existing code)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_user()
    app.run(host='0.0.0.0', port=5000)
