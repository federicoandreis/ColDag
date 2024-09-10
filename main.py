from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Project, Role, UserActivity, PasswordHistory
from config import Config
import os
import json
from io import BytesIO
from datetime import datetime, timedelta
import secrets
from flask_mail import Mail, Message
import logging
from sqlalchemy.exc import SQLAlchemyError
import re
import pyotp
import qrcode
import base64

app = Flask(__name__)
app.config.from_object(Config)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
app.logger.info(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

mail = Mail(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_user_activity(user_id, activity_type, details=None):
    new_activity = UserActivity(user_id=user_id, activity_type=activity_type, details=details)
    db.session.add(new_activity)
    db.session.commit()

def is_password_strong(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            user = User.query.filter_by(username=username).first()
            if user:
                if user.account_locked_until and user.account_locked_until > datetime.utcnow():
                    flash('Account is locked. Please try again later.')
                    return redirect(url_for('login'))
                
                if user and check_password_hash(user.password, password):
                    if not user.email_verified:
                        flash('Please verify your email before logging in.')
                        return redirect(url_for('login'))
                    if user.is_password_expired():
                        flash('Your password has expired. Please change your password.')
                        return redirect(url_for('change_expired_password', user_id=user.id))
                    if user.two_factor_secret:
                        session['user_id'] = user.id
                        return redirect(url_for('two_factor_auth'))
                    login_user(user)
                    user.last_login = datetime.utcnow()
                    user.failed_login_attempts = 0
                    db.session.commit()
                    log_user_activity(user.id, 'login', 'User logged in successfully')
                    return redirect(url_for('index'))
                else:
                    user.failed_login_attempts += 1
                    if user.failed_login_attempts >= 5:
                        user.account_locked_until = datetime.utcnow() + timedelta(minutes=15)
                        flash('Too many failed login attempts. Account locked for 15 minutes.')
                        log_user_activity(user.id, 'account_locked', 'Account locked due to multiple failed login attempts')
                    else:
                        flash('Invalid username or password')
                    db.session.commit()
            else:
                flash('Invalid username or password')
        except SQLAlchemyError as e:
            app.logger.error(f"Database error during login: {str(e)}")
            flash('An error occurred. Please try again later.')
    return render_template('login.html')

@app.route('/two_factor_auth', methods=['GET', 'POST'])
def two_factor_auth():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form.get('token')
        if user.verify_totp(token):
            login_user(user)
            user.last_login = datetime.utcnow()
            user.failed_login_attempts = 0
            db.session.commit()
            log_user_activity(user.id, 'login', 'User logged in successfully with 2FA')
            session.pop('user_id', None)
            return redirect(url_for('index'))
        else:
            flash('Invalid 2FA token. Please try again.')

    return render_template('two_factor_auth.html')

@app.route('/profile/enable_2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    if request.method == 'POST':
        token = request.form.get('token')
        if current_user.verify_totp(token):
            current_user.two_factor_secret = pyotp.random_base32()
            db.session.commit()
            log_user_activity(current_user.id, '2fa_enabled', 'User enabled 2FA')
            flash('Two-factor authentication has been enabled.')
            return redirect(url_for('profile'))
        else:
            flash('Invalid token. Please try again.')

    if not current_user.two_factor_secret:
        current_user.two_factor_secret = pyotp.random_base32()
        db.session.commit()

    totp_uri = current_user.get_totp_uri()
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_code = base64.b64encode(buffered.getvalue()).decode()

    return render_template('enable_2fa.html', qr_code=qr_code)

@app.route('/profile/disable_2fa', methods=['POST'])
@login_required
def disable_2fa():
    current_user.two_factor_secret = None
    db.session.commit()
    log_user_activity(current_user.id, '2fa_disabled', 'User disabled 2FA')
    flash('Two-factor authentication has been disabled.')
    return redirect(url_for('profile'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not is_password_strong(password):
            flash('Password is not strong enough. It must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.')
            return render_template('register.html')
        
        try:
            if User.query.filter_by(username=username).first():
                flash('Username already exists')
            elif User.query.filter_by(email=email).first():
                flash('Email already exists')
            else:
                user_role = Role.query.filter_by(name='user').first()
                if not user_role:
                    user_role = Role(name='user', description='Regular user')
                    db.session.add(user_role)
                    db.session.commit()
                
                new_user = User(username=username, email=email, password=generate_password_hash(password), role=user_role)
                db.session.add(new_user)
                db.session.commit()
                log_user_activity(new_user.id, 'account_created', 'User account created')
                flash('Registration successful. Please check your email to verify your account.')
                return redirect(url_for('login'))
        except SQLAlchemyError as e:
            db.session.rollback()
            app.logger.error(f"Database error during registration: {str(e)}")
            flash('An error occurred. Please try again later.')
    return render_template('register.html')

@app.route('/')
@login_required
def index():
    return render_template('index.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
