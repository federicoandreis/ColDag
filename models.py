from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta
import secrets
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask import current_app

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    registered_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    email_confirmed = db.Column(db.Boolean, default=False)
    email_confirmation_token = db.Column(db.String(100), unique=True, nullable=True)
    profile = db.relationship('UserProfile', backref='user', uselist=False, cascade='all, delete-orphan')
    projects = db.relationship('Project', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    def generate_email_confirmation_token(self):
        self.email_confirmation_token = secrets.token_urlsafe(32)
        return self.email_confirmation_token

    def generate_password_reset_token(self):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_password_reset_token(token, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=expiration)
        except:
            return None
        return User.query.get(data['user_id'])

    def lock_account(self, duration_minutes=30):
        self.locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        self.failed_login_attempts = 0
        db.session.commit()

    def unlock_account(self):
        self.locked_until = None
        self.failed_login_attempts = 0
        db.session.commit()

    def increment_failed_attempts(self):
        self.failed_login_attempts += 1
        db.session.commit()

class UserProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    full_name = db.Column(db.String(100), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(100), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    avatar = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
