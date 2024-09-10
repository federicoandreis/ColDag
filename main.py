from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Project
from config import Config
import os
import json
from io import BytesIO
import networkx as nx
from flask_mail import Mail, Message
import datetime
from sqlalchemy import inspect

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_default_user():
    username = 'fede'
    password = 'admin'
    email = 'admin@example.com'
    if not User.query.filter_by(username=username).first():
        new_user = User(username=username, email=email, is_admin=True, is_active=True)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        print(f"Default user '{username}' created.")
    else:
        print(f"Default user '{username}' already exists.")

def update_database_schema():
    inspector = inspect(db.engine)
    if not inspector.has_table("user"):
        db.create_all()
        print("Database tables created.")
    else:
        existing_columns = set(column['name'] for column in inspector.get_columns("user"))
        model_columns = set(column.key for column in User.__table__.columns)
        missing_columns = model_columns - existing_columns
        if missing_columns:
            print(f"Adding missing columns to user table: {missing_columns}")
            with db.engine.connect() as conn:
                for column in missing_columns:
                    conn.execute(f'ALTER TABLE "user" ADD COLUMN {column} {User.__table__.columns[column].type}')
            print("Database schema updated.")
        else:
            print("Database schema is up to date.")

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
        if user and user.check_password(password):
            if user.is_active:
                login_user(user)
                user.last_login = datetime.datetime.utcnow()
                db.session.commit()
                return redirect(url_for('index'))
            else:
                flash('Please confirm your email address before logging in.')
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
        elif User.query.filter_by(email=email).first():
            flash('Email already exists')
        else:
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            
            token = new_user.generate_confirmation_token()
            confirm_url = url_for('confirm_email', token=token, _external=True)
            html = render_template('email/confirm.html', confirm_url=confirm_url)
            subject = "Please confirm your email"
            send_email(new_user.email, subject, html)
            
            flash('A confirmation email has been sent to your email address.')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/confirm/<token>')
def confirm_email(token):
    user = User.query.filter_by(email=request.args.get('email')).first_or_404()
    if user.is_active:
        flash('Account already confirmed. Please login.')
    elif user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('login'))

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = user.generate_reset_token()
            reset_url = url_for('reset_password', token=token, _external=True)
            html = render_template('email/reset_password.html', reset_url=reset_url)
            subject = "Password Reset Request"
            send_email(user.email, subject, html)
            flash('An email with instructions to reset your password has been sent to you.')
        else:
            flash('Email address not found.')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        password = request.form.get('password')
        if User.reset_password(token, password):
            flash('Your password has been updated.')
            return redirect(url_for('login'))
        else:
            flash('The reset link is invalid or has expired.')
    return render_template('reset_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    username = request.form.get('username')
    email = request.form.get('email')
    
    if username != current_user.username and User.query.filter_by(username=username).first():
        flash('Username already exists')
    elif email != current_user.email and User.query.filter_by(email=email).first():
        flash('Email already exists')
    else:
        current_user.username = username
        current_user.email = email
        db.session.commit()
        flash('Profile updated successfully')
    
    return redirect(url_for('profile'))

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

# ... (keep the existing routes and functions)

if __name__ == '__main__':
    with app.app_context():
        update_database_schema()
        create_default_user()
    app.run(host='0.0.0.0', port=5000, debug=True)
