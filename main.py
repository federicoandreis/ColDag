from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Project, Role, UserActivity
from config import Config
import os
import json
from io import BytesIO
import networkx as nx
from flask_mail import Mail, Message
import datetime
from sqlalchemy import inspect, text

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_user_activity(user, activity_type, details=None):
    activity = UserActivity(user_id=user.id, activity_type=activity_type, details=details)
    db.session.add(activity)
    db.session.commit()

def update_database_schema():
    with app.app_context():
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
                    for column_name in missing_columns:
                        column = User.__table__.columns[column_name]
                        column_type = column.type
                        if isinstance(column_type, db.DateTime):
                            column_type = 'TIMESTAMP'
                        conn.execute(text(f'ALTER TABLE "user" ADD COLUMN {column_name} {column_type}'))
                    conn.commit()
                print("Database schema updated.")
            else:
                print("Database schema is up to date.")

def create_default_user():
    with app.app_context():
        admin_role = Role.query.filter_by(name='Admin').first()
        if not admin_role:
            admin_role = Role(name='Admin')
            db.session.add(admin_role)
            db.session.commit()

        user_role = Role.query.filter_by(name='User').first()
        if not user_role:
            user_role = Role(name='User')
            db.session.add(user_role)
            db.session.commit()

        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(username='admin', email='admin@example.com', is_admin=True, is_active=True, role=admin_role)
            admin_user.set_password('admin')  # Set the password using the set_password method
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created.")
        else:
            print("Default admin user already exists.")

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
                log_user_activity(user, 'login')
                return redirect(url_for('index'))
            else:
                flash('Please confirm your email address before logging in.')
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_user_activity(current_user, 'logout')
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/user_activity')
@login_required
def user_activity():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))
    activities = UserActivity.query.order_by(UserActivity.timestamp.desc()).limit(100).all()
    return render_template('user_activity.html', activities=activities)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))
    users = User.query.all()
    roles = Role.query.all()
    projects = Project.query.all()
    return render_template('admin.html', users=users, roles=roles, projects=projects)

@app.route('/admin/toggle_admin/<int:user_id>')
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('index'))
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    log_user_activity(current_user, 'toggle_admin', f"Changed admin status for user {user.username}")
    flash(f"Admin status for {user.username} has been {'granted' if user.is_admin else 'revoked'}.")
    return redirect(url_for('admin'))

@app.route('/admin/toggle_active/<int:user_id>')
@login_required
def toggle_active(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('index'))
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    log_user_activity(current_user, 'toggle_active', f"Changed active status for user {user.username}")
    flash(f"Account for {user.username} has been {'activated' if user.is_active else 'deactivated'}.")
    return redirect(url_for('admin'))

@app.route('/admin/change_role/<int:user_id>', methods=['POST'])
@login_required
def change_role(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.')
        return redirect(url_for('index'))
    user = User.query.get_or_404(user_id)
    new_role_id = request.form.get('role_id')
    new_role = Role.query.get(new_role_id)
    if new_role:
        old_role = user.role
        user.role = new_role
        db.session.commit()
        log_user_activity(current_user, 'change_role', f"Changed role for user {user.username} from {old_role.name} to {new_role.name}")
        flash(f"Role for {user.username} has been changed to {new_role.name}.")
    else:
        flash("Invalid role selected.")
    return redirect(url_for('admin'))

if __name__ == '__main__':
    with app.app_context():
        update_database_schema()
        create_default_user()
    app.run(host='0.0.0.0', port=5000, debug=True)
