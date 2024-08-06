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
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args': {'timeout': 15}  # timeout set to 15 seconds
}

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
    print('OTP sent: ', otp)
    mail.send(msg)


def send_mail(email,  message):
    msg = Message(f'New message on Wallet. You have been successfully registered on Amebo Wallet. You also received ₦100,000.00 as your sign up bonus. Thank you',   sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = message
    
    mail.send(msg)


# Function to give users 100,000 after registration
def give_100k(email):
    from models import User
    user = User.query.filter_by(email=email).first()
    user.wallet_balance = 100000
    db.session.commit()



@app.route('/')
def index():
    return render_template('index.html')



@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    from models import User 

    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'danger')
            return redirect(url_for('sign_up'))
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('sign_up'))
        else:
            hashed_password = sha256_crypt.hash(password)
            user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            # Send otp code
            otp = str(random.randint(1000, 9999))
            session['otp'] = otp
            send_otp(email, otp)
            print(email, otp)
            flash('Registration successful. Please check your email for verification token.', 'success')

            return redirect(url_for('token', email=email))
        
    return render_template('sign_up.html')


@app.template_filter('mask_email')
def mask_email(email):
    return email[:4] + '***'


@app.route('/token/<email>', methods=['GET', 'POST'])
def token(email):
    if request.method == 'POST':
        otp = request.form['otp']
        print(f'Entered OTP: {otp}')
        print(f'Session OTP: {session.get("otp")}')
        if otp == session.get('otp'):
            send_mail(email, 'You have successfully registered on Amebo Wallet. You also received ₦100,000.00 as your sign up bonus. Thank you')
            give_100k(email)
            flash('Registration successful. You can now login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    return render_template('token.html', email=email)



@app.route('/login', methods=['GET', 'POST'])
def login():
    from models import User
    if request.method == 'POST':
        email = request.form['email']
        password= request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and sha256_crypt.verify(password, user.password):
            login_user(user)
            flash('You are now logged in', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))



@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    from models import User
    user = current_user 
    if user:
        user_data = {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'wallet_balance': user.wallet_balance

        }
    return render_template('dashboard.html', user=user_data)
    