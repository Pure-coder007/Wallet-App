from flask import Flask, render_template, request, redirect, session, url_for, flash
# import mysql.connector
# from mysql.connector import Error
from email_validator import validate_email, EmailNotValidError
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
import random
from flask_mail import Mail, Message
# from db_setup import setup_database, config
from datetime import datetime
from passlib.hash import pbkdf2_sha256 as sha256_crypt
# from werkzeug.utils import secure_filename
import os
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
# from flask_uploads import UploadSet, configure_uploads, IMAGES
import calendar
from datetime import datetime
# from models import get_user, add_user, get_all_users, User, get_user_id, get_worker, add_worker, contact_me, update_user_profile, Worker, get_worker_id, gen_ran_string, Admin, add_admin, get_admin_id, update_worker_profile

import cloudinary
import cloudinary.uploader
import string

cloudinary.config(
    cloud_name = "duyoxldib",
    api_key = "778871683257166", 
  api_secret = "NM2WHVuvMytyfnVziuzRScXrrNk"
)


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myapp.db'
app.config['SECRET_KEY'] = 'thisismysecretkey'

db = SQLAlchemy(app)


@app.route('/')
def index():
    return render_template('index.html')



