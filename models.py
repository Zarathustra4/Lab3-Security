from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=False, nullable=False)
    confirmed = db.Column(db.Boolean(), nullable=False, default=False)
    is_admin = db.Column(db.Boolean(), nullable=False, default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    last_failed_attempt = db.Column(db.DateTime, default=datetime.now())
    oauth_provider = db.Column(db.String(50), nullable=True)
    oauth_id = db.Column(db.String(200), nullable=True)


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now())
    is_admin = db.Column(db.Boolean(), nullable=False, default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    last_failed_attempt = db.Column(db.DateTime, default=datetime.now())


