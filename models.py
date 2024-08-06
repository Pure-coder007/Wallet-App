from datetime import datetime
from app import db, login_manager, bcrypt, secret_key
from flask_login import UserMixin
from flask import current_app
import os
import secrets
import json



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(20), nullable=False)
    last_name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    nin = db.Column(db.String(50), unique=True, nullable=True)
    bvn = db.Column(db.String(50), unique=True, nullable=True)
    profile_pic = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(50), unique=True, nullable=True)
    utility_bill = db.Column(db.String(100), nullable=True)
    wallet_balance = db.Column(db.Float, nullable=False, default=0.00)


    def __repr__(self):
        return f"User('{self.email}', '{self.password}')"