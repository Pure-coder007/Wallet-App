from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin
from flask import current_app
import os
import secrets
import json
from flask_sqlalchemy import SQLAlchemy







@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    nin = db.Column(db.Integer(), unique=True, nullable=True)
    bvn = db.Column(db.Integer(), unique=True, nullable=True)
    profile_pic = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(), unique=True, nullable=True)
    utility_bill = db.Column(db.String(100), nullable=True)
    wallet_balance = db.Column(db.Float, nullable=False, default=0.00)
    card_number = db.Column(db.Integer(), unique=True, nullable=False)
    card_back = db.Column(db.Integer(), unique=True, nullable=False)
    card_expiry = db.Column(db.String(50), nullable=False)
    transaction_pin = db.Column(db.Integer(), unique=True)


    def __repr__(self):
        return f"User('{self.email}', '{self.password}')"
    

class TransactionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(120))
    amount = db.Column(db.Float)
    receiver = db.Column(db.String(120))
    transaction_type = db.Column(db.String(20))
    sender_account = db.Column(db.String(20))
    receiver_account = db.Column(db.String(20))
    bank_name = db.Column(db.String(20))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    transaction_ref = db.Column(db.String(20), unique=True)
    electricity_token = db.Column(db.String(2000))
    session_id = db.Column(db.String(2000))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    phone_number = db.Column(db.String(20), unique=True)
    narration = db.Column(db.String(2000))

    def __repr__(self):
        return f"TransactionHistory(' '{self.amount}', '{self.transaction_type}', '{self.date}')"






