from flask import Flask, render_template, request, redirect, session, url_for, flash, session, g
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
from datetime import datetime, timedelta
from flask_migrate import Migrate


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
migrate = Migrate(app, db) 




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



# Generating 16 digits for user card
def generate_card():
    return ''.join(random.choices(string.digits, k=16))



# Generating 3 digits for back of card
def generate_back():
    return ''.join(random.choices(string.digits, k=3))


# Card Expiry 4 years after registration
def expiry_date():
    return datetime.now() + timedelta(days=1460)



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
        phone_number = request.form['phone_number']
        card_number = generate_card()
        card_back = generate_back()
        card_expiry = expiry_date()
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
            user = User(first_name=first_name, last_name=last_name, email=email, password=hashed_password, phone_number=phone_number, card_number=card_number, card_back=card_back, card_expiry=card_expiry)
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
        # Convert the card number to a string and format it with spaces
        card_number = str(user.card_number) if user.card_number else ""
        card_number_formatted = '     '.join(card_number[i:i+4] for i in range(0, len(card_number), 4)) if card_number else ""

        # Format the card expiry to only show month and year
        card_expiry = user.card_expiry
        card_expiry_formatted = ""
        if card_expiry:
            card_exp = datetime.strptime(card_expiry, '%Y-%m-%d %H:%M:%S.%f')
            card_expiry_formatted = card_exp.strftime('%m/%y')

        user_data = {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'wallet_balance': user.wallet_balance, 
            'phone_number': user.phone_number,
            'card_number_formatted': card_number_formatted,
            'card_back': user.card_back,
            'card_expiry_formatted': card_expiry_formatted
        }

        print('i am here')
        print(user_data, '11111111111111')
    return render_template('dashboard.html', user=user_data)






# Edit User Profile
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        
        profile_pic = request.files['profile_pic']
        user = current_user
        if profile_pic:
            filename = secure_filename(profile_pic.filename)
            response = cloudinary.uploader.upload(profile_pic, public_id=f"user/{filename}")
            profile_pic = response['secure_url']
        
        
        db.session.commit()
        flash('Your profile has been updated', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html')

