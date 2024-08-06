from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField
from werkzeug.utils import secure_filename
from email_validator import validate_email, EmailNotValidError
from passlib.hash import pbkdf2_sha256 as sha256_crypt
from flask_bcrypt import Bcrypt
import cloudinary
import cloudinary.uploader
import random
import os
import calendar
import string
from datetime import datetime

# Configuring Cloudinary
cloudinary.config(
    cloud_name="duyoxldib",
    api_key="778871683257166",
    api_secret="NM2WHVuvMytyfnVziuzRScXrrNk"
)

# Initializing Flask application
app = Flask(__name__)

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wallet_app.db'
secret_key =  'ssdfghjklreaertyuiytrewertyulhe3678oiytr43567iuiuytrewrtuyr3455'
app.config['SECRET_KEY'] = 'thisismysecretkey'

# Initializing extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

# Login configurations
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'




# flask mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'kingsleydike318@gmail.com'
app.config['MAIL_PASSWORD'] = 'ucgwnjifgohbnskl'
MAIL_USE_TLS = False
SECRET_KEY = 'language007'


# Flask Mail Configuration
mail = Mail(app)

def send_otp(email, otp):
    msg = Message('Verification Token', sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f'Your verification token is {otp}'
    print('otp : ', otp)
    mail.send(msg)


def send_mail(email,  message):
    msg = Message(f'New message on ServiceHub. Login to see message {"serviceshub.onrender.com/user_dashboard/home"}',   sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = message
    
    mail.send(msg)


    

@app.route('/')
def index():
    return render_template('index.html')



@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    return render_template('sign_up.html')




@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')