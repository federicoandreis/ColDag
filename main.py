import re
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, UserProfile, Project
from config import Config
import os
import json
from io import BytesIO
import networkx as nx
from datetime import datetime, timedelta
from functools import wraps
import secrets
from flask_mail import Mail, Message

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

mail = Mail(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def create_default_user():
    username = 'fede'
    password = 'admin'
    email = 'fede@example.com'
    if not User.query.filter_by(username=username).first():
        new_user = User(username=username, email=email, password=generate_password_hash(password), is_admin=True, email_confirmed=True)
        db.session.add(new_user)
        db.session.commit()
        print(f"Default user '{username}' created.")
    else:
        print(f"Default user '{username}' already exists.")

def send_verification_email(user):
    token = user.generate_email_confirmation_token()
    msg = Message('Confirm Your Email',
                  sender='noreply@yourdomain.com',
                  recipients=[user.email])
    msg.body = f'''To confirm your email, visit the following link:
{url_for('verify_email', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

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

def send_password_reset_email(user):
    token = user.generate_password_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@yourdomain.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_password', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)

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
        
        if user:
            if user.locked_until and user.locked_until > datetime.utcnow():
                flash('Your account is temporarily locked. Please try again later.', 'error')
                return redirect(url_for('login'))
            
            if check_password_hash(user.password, password):
                if not user.is_active:
                    flash('Your account is deactivated. Please contact an administrator.', 'error')
                    return redirect(url_for('login'))
                if not user.email_confirmed:
                    flash('Please confirm your email before logging in.', 'warning')
                    return redirect(url_for('login'))
                
                login_user(user)
                user.last_login = datetime.utcnow()
                user.failed_login_attempts = 0
                db.session.commit()
                return redirect(url_for('index'))
            else:
                user.increment_failed_attempts()
                if user.failed_login_attempts >= 5:
                    user.lock_account()
                    flash('Too many failed login attempts. Your account has been temporarily locked.', 'error')
                else:
                    flash('Invalid username or password')
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
        elif not is_password_strong(password):
            flash('Password is not strong enough. It should be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.')
        else:
            new_user = User(username=username, email=email, password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            send_verification_email(new_user)
            flash('Registration successful. Please check your email to verify your account.')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            send_password_reset_email(user)
            flash('An email has been sent with instructions to reset your password.', 'info')
        else:
            flash('No account found with that email address.', 'error')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.verify_password_reset_token(token)
    if not user:
        flash('Invalid or expired token', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
        elif not is_password_strong(password):
            flash('Password is not strong enough. It should be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.')
        else:
            user.password = generate_password_hash(password)
            user.unlock_account()  # Unlock the account when resetting password
            db.session.commit()
            flash('Your password has been reset.', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    user = User.query.filter_by(email_confirmation_token=token).first()
    if user:
        user.email_confirmed = True
        user.email_confirmation_token = None
        db.session.commit()
        flash('Your email has been confirmed. You can now login.', 'success')
    else:
        flash('The confirmation link is invalid or has expired.', 'danger')
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if not current_user.profile:
        current_user.profile = UserProfile()
        db.session.commit()

    if request.method == 'POST':
        current_user.profile.full_name = request.form.get('full_name')
        current_user.profile.bio = request.form.get('bio')
        current_user.profile.location = request.form.get('location')
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html')

@app.route('/admin')
@login_required
@admin_required
def admin():
    projects = Project.query.all()
    return render_template('admin.html', projects=projects)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/toggle_user/<int:user_id>')
@login_required
@admin_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user != current_user:
        user.is_active = not user.is_active
        db.session.commit()
        flash(f"User {user.username} has been {'activated' if user.is_active else 'deactivated'}.", 'success')
    else:
        flash("You cannot deactivate your own account.", 'error')
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_user/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user != current_user and not user.is_admin:
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.username} has been deleted.", 'success')
    else:
        flash("You cannot delete your own account or another admin account.", 'error')
    return redirect(url_for('admin_users'))

@app.route('/admin/toggle_admin/<int:user_id>')
@login_required
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user != current_user:
        user.is_admin = not user.is_admin
        db.session.commit()
        flash(f"Admin status for {user.username} has been {'granted' if user.is_admin else 'revoked'}.", 'success')
    else:
        flash("You cannot change your own admin status.", 'error')
    return redirect(url_for('admin_users'))

@app.route('/admin/reset_password/<int:user_id>')
@login_required
@admin_required
def reset_password_admin(user_id):
    user = User.query.get_or_404(user_id)
    new_password = secrets.token_urlsafe(12)
    user.password = generate_password_hash(new_password)
    db.session.commit()
    flash(f"Password for {user.username} has been reset. New password: {new_password}", 'success')
    return redirect(url_for('admin_users'))

# ... (keep the rest of the existing routes)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_user()
    app.run(host='0.0.0.0', port=5000)
