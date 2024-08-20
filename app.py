from flask import Flask, render_template, request, redirect, session, url_for, flash, session, g, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlite3 import IntegrityError
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
from flask_wtf.csrf import CSRFProtect






# Configuring Cloudinary
cloudinary.config(
    cloud_name="duyoxldib",
    api_key="778871683257166",
    api_secret="NM2WHVuvMytyfnVziuzRScXrrNk"
)

# Initializing Flask application
app = Flask(__name__)



# Apply CSRF protection
# csrf = CSRFProtect(app)


# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wallet_app.db'
secret_key =  'ssdfghjklreaertyuiytrewertyulhe3678oiytr43567iuiuytrewrtuyr3455'
app.config['SECRET_KEY'] = 'thisismysecretkey'
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'connect_args': {'timeout': 15}  # timeout set to 15 seconds
}

# Initializing extensions
from sqlalchemy import MetaData


naming_convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

db = SQLAlchemy(app, metadata=MetaData(naming_convention=naming_convention))
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

# register models
from models import User, TransactionHistory


@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'TransactionHistory': TransactionHistory}


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

        # Basic validation
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'danger')
            return redirect(url_for('sign_up'))
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('sign_up'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please log in.', 'danger')
            return redirect(url_for('sign_up'))
        
        try:
            # Hash password and save user
            hashed_password = sha256_crypt.hash(password)
            user = User(
                first_name=first_name, last_name=last_name, 
                email=email, password=hashed_password, 
                phone_number=phone_number, 
                card_number=card_number, card_back=card_back, 
                card_expiry=card_expiry
            )
            db.session.add(user)
            db.session.commit()

            # Generate and send OTP
            otp = str(random.randint(1000, 9999))
            session['otp'] = otp
            send_otp(email, otp)
            flash('Registration successful. Please check your email for verification token.', 'success')
            return redirect(url_for('token', email=email))
        
        except Exception as e:
            print(e, 'hgjertygrtgrtrsthsrhtrsthrhrhtrhtrhtrhrhtrhtrt')
            db.session.rollback()  # Rollback the transaction in case of error
            flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('sign_up'))
        
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
            send_mail(
                email=email,
                subject="Welcome to Amebo Wallet!",
                message_body="You have been successfully registered on Amebo Wallet. You also received ₦100,000.00 as your sign-up bonus. Thank you!"
                )
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
    user = current_user
    from models import TransactionHistory


    if user:
        # Getting Transaction History and format the date to display it like 'Jan 1st 2023'
        transactions = TransactionHistory.query.filter_by(user_id=user.id).order_by(TransactionHistory.date.desc()).all()
        for transaction in transactions:
            transaction.date = transaction.date.strftime('%b %d %Y')
        print(transactions)

    
    # if user:
    #     get_recent_transactions(user.id)


    # # transactions = TransactionHistory.query.filter_by(user_id=user.id).order_by(TransactionHistory.date.desc()).all()



    print(request.method, 'REQUEST')

    if request.method == 'POST':
        transaction_pin = request.form.get('transaction_pin')
        confirm_pin = request.form.get('confirm_pin')

        if transaction_pin != confirm_pin:
            flash('Transaction PINs do not match', 'warning')
            return redirect(url_for('dashboard'))

        # hash the transaction pin
        user.transaction_pin = sha256_crypt.hash(transaction_pin)

        db.session.commit()

        flash('Transaction PIN set successfully!', 'success')
        return render_template('dashboard.html', user=user)

    if user:
        card_number = str(user.card_number) if user.card_number else ""
        card_number_formatted = '     '.join(card_number[i:i+4] for i in range(0, len(card_number), 4)) if card_number else ""

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

    return render_template('dashboard.html', user=user_data, transactions=transactions)









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
            print(response, 'eeeeeeeeeeeeeeee')
            user.profile_pic = response['secure_url']
            print(user.profile_pic, 'yyyyyyyyyyyyyyyyyyyyy')
        print(profile_pic, '22222222222222222222222222222222')
        db.session.commit()
        flash('Your profile has been updated', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html')







# Send to wallet
@app.route('/send_to_wallet', methods=['GET', 'POST'])
def send_to_wallet():
    user = current_user
    
    if request.method == 'POST':
        phone_number = request.form.get('phone_number')
        amount = request.form.get('amount')
        message = request.form.get('message')

        recipient = User.query.filter_by(phone_number=phone_number).first()
        if not recipient:
            flash('Account number not found', 'danger')
            return redirect(url_for('send_to_wallet'))
        if recipient.phone_number == user.phone_number:
            flash('You cannot send money to yourself', 'danger')
            return redirect(url_for('send_to_wallet'))
        print(amount, 'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ')
        if user.wallet_balance < int(amount):
            flash('Insufficient funds', 'danger')
            return redirect(url_for('send_to_wallet'))

        # Store relevant data in session for access in the next route
        session['recipient_phone'] = phone_number
        session['amount'] = amount
        session['message'] = message

        return redirect(url_for('final_wallet', acct_number=phone_number))
    
    return render_template('send_to_wallet.html')




# Generate session_id of 15 digits
def generate_session_id():
    return ''.join(random.choices(string.digits, k=28))


# Generate transaction_ref consisting of 10 digits including letters and /, for example: 123/SSD/DASDsd/33eedwaqwe/34ASDW
import uuid

def generate_transaction_ref():
    while True:
        # Generate a UUID-based reference string
        transaction_ref = str(uuid.uuid4()).replace('-', '')[:20]  # or adjust length as needed

        # Check if the generated reference already exists
        existing_transaction = TransactionHistory.query.filter_by(transaction_ref=transaction_ref).first()
        if not existing_transaction:
            return transaction_ref

        # Optionally, add a counter or timestamp to ensure uniqueness if collisions happen frequently



def send_mail(email, subject, message_body):
    msg = Message(subject=subject, 
                  sender=app.config['MAIL_USERNAME'], 
                  recipients=[email])
    msg.body = message_body
    
    mail.send(msg)





# Generating an email to the sender and receiver of the transaction

def send_receipt_email(email, transaction_details):
    subject = "Transaction Receipt from Amebo Wallet"

    # HTML email content with a table and logo
    message_body = f"""
    <html>
    <body>
        <div style="text-align: center;">
            <img src="https://res.cloudinary.com/duyoxldib/image/upload/v1724157721/Untitled_design_2_1_hngomm.png" alt="Amebo Wallet Logo" style="width:150px; height:auto;"/>
        </div>
        <h3>Transaction Receipt</h3>
        <p>Thank you for using Amebo Wallet. Below are the details of your recent transaction:</p>
        <table border="1" cellpadding="10" cellspacing="0" style="width:100%; border-collapse: collapse;">
            <tr>
                <th style="text-align: left;">Transaction Type</th>
                <td>{transaction_details['transaction_type']}</td>
            </tr>
            <tr>
                <th style="text-align: left;">Amount</th>
                <td>₦{transaction_details['amount']}</td>
            </tr>

            <tr>
                <th style="text-align: left;">Current Balance</th>
                <td>₦{transaction_details['wallet_balance']}</td>
            </tr>
            <tr>
                <th style="text-align: left;">Sender</th>
                <td>{transaction_details['sender']}</td>
            </tr>
            <tr>
                <th style="text-align: left;">Receiver</th>
                <td>{transaction_details['receiver']}</td>
            </tr>
            <tr>
                <th style="text-align: left;">Date</th>
                <td>{transaction_details['date']}</td>
            </tr>
            <tr>
                <th style="text-align: left;">Transaction Reference</th>
                <td>{transaction_details['transaction_ref']}</td>
            </tr>

            <tr>
                <th style="text-align: left;">Remark</th>
                <td>{transaction_details['narration']}</td>
            </tr>
        </table>
        <br>
        <p><p style="font-weight:600;">Remember:</p> Keep your your pin and login information safe. Do not respond to emails requesting for your login/PIN details.</p>
        <br>
        <p>We appreciate your continued trust in us.</p>
        <p>Best regards,<br>The Amebo Wallet Team</p>
    </body>
    <br>
    <br>
    </html>
    <br>
    <br>
    """

    msg = Message(subject=subject, 
                  sender=app.config['MAIL_USERNAME'], 
                  recipients=[email])
    
    # Set the HTML body
    msg.html = message_body

    mail.send(msg)





@app.route('/final_wallet/<acct_number>', methods=['GET', 'POST'])
def final_wallet(acct_number):
    from models import User, TransactionHistory, Receipts
    from sqlite3 import IntegrityError

    user = current_user
    account_owner = User.query.filter_by(phone_number=acct_number).first()
    
    if not account_owner:
        flash('Account number not found', 'danger')
        return redirect(url_for('send_to_wallet'))
    
    # Retrieve and parse data from session
    format_amount = session.get('amount', 0)
    amount_float = float(format_amount)
    formatted_amount = "{:,.0f}".format(amount_float)
    formatted_amount_receipt = "{:,.0f}".format(amount_float)
    
    message = session.get('message')

    if request.method == 'POST':
        transaction_pin = request.form['pin']
        if sha256_crypt.verify(transaction_pin, user.transaction_pin):
            user.wallet_balance -= amount_float
            account_owner.wallet_balance += amount_float
            
            session_id = generate_session_id()

            while True:
                transaction_ref = generate_transaction_ref()

                # Record debit and credit transactions
                debit_transaction = TransactionHistory(
                    user_id=user.id,
                    sender=user.first_name + ' ' + user.last_name,
                    receiver=account_owner.first_name + ' ' + account_owner.last_name,
                    amount=amount_float,
                    narration=message,
                    transaction_type='Debit',
                    sender_account=user.phone_number,
                    receiver_account=account_owner.phone_number,
                    bank_name='Wallet Transfer',
                    date=datetime.utcnow(),
                    transaction_ref=transaction_ref,
                    session_id=session_id,
                    wallet_balance=user.wallet_balance
                )
                print(debit_transaction, "DEBIT")

                

                credit_transaction = TransactionHistory(
                    user_id=account_owner.id,
                    sender=user.first_name + ' ' + user.last_name,
                    receiver=account_owner.first_name + ' ' + account_owner.last_name,
                    amount=amount_float,
                    narration=message,
                    transaction_type='Credit',
                    sender_account=user.phone_number,
                    receiver_account=account_owner.phone_number,
                    bank_name='Wallet Transfer',
                    date=datetime.utcnow(),
                    transaction_ref=transaction_ref,
                    session_id=session_id,
                    wallet_balance=account_owner.wallet_balance
                )

                print(credit_transaction, "credit")


                # Create receipts for both sender and receiver
                receipt_transaction_sender = Receipts(
                    sender=user.first_name + ' ' + user.last_name,
                    amount=amount_float,
                    receiver=account_owner.first_name + ' ' + account_owner.last_name,
                    transaction_type='Debit',
                    sender_account=user.phone_number,
                    receiver_account=account_owner.phone_number,
                    bank_name='Wallet Transfer',
                    date=datetime.utcnow(),
                    transaction_ref=transaction_ref,
                    session_id=session_id,
                    narration=message,
                    wallet_balance=user.wallet_balance
                )

                print(receipt_transaction_sender, "receipt_transaction_sender")


                receipt_transaction_receiver = Receipts(
                    sender=user.first_name + ' ' + user.last_name,
                    amount=amount_float,
                    receiver=account_owner.first_name + ' ' + account_owner.last_name,
                    transaction_type='Credit',
                    sender_account=user.phone_number,
                    receiver_account=account_owner.phone_number,
                    bank_name='Wallet Transfer',
                    date=datetime.utcnow(),
                    transaction_ref=transaction_ref,
                    session_id=session_id,
                    narration=message,
                    wallet_balance=account_owner.wallet_balance
                )
                print(receipt_transaction_receiver, "receipt_transaction_receiver")
                

                try:
                    db.session.add(debit_transaction)
                    db.session.add(credit_transaction)
                    db.session.add(receipt_transaction_sender)
                    db.session.add(receipt_transaction_receiver)
                    db.session.commit()

                    # format the wallet balance
                    formatted_wallet_balance = "{:,.0f}".format(user.wallet_balance)
                    formatted_wallet_balance_receipt = "{:,.0f}".format(account_owner.wallet_balance)

                    # Send email receipts to both sender and receiver
                    transaction_details_sender = {
                        "transaction_type": "Debit",
                        "amount": formatted_amount_receipt,
                        "sender": user.first_name + ' ' + user.last_name,
                        "receiver": account_owner.first_name + ' ' + account_owner.last_name,
                        "date": datetime.utcnow().strftime('%b %d, %Y %I:%M %p'),
                        "transaction_ref": transaction_ref,
                        "narration": message,
                        "wallet_balance": formatted_wallet_balance
                    }

                    transaction_details_receiver = {
                        "transaction_type": "Credit",
                        "amount": formatted_amount_receipt,
                        "sender": user.first_name + ' ' + user.last_name,
                        "receiver": account_owner.first_name + ' ' + account_owner.last_name,
                        "date": datetime.utcnow().strftime('%b %d, %Y %I:%M %p'),
                        "transaction_ref": transaction_ref,
                        "narration": message,
                        "wallet_balance": formatted_wallet_balance_receipt
                    }

                    send_receipt_email(user.email, transaction_details_sender)  # Email to sender
                    send_receipt_email(account_owner.email, transaction_details_receiver)  # Email to receiver

                    session.pop('recipient_phone', None)
                    session.pop('amount', None)
                    session.pop('message', None)

                    # Format date for display
                    formatted_date = datetime.utcnow().strftime('%b %d, %Y %I:%M %p')
                    formatted_date = formatted_date.replace(' 1,', ' 1st,').replace(' 2,', ' 2nd,').replace(' 3,', ' 3rd,').replace(' 21,', ' 21st,').replace(' 22,', ' 22nd,').replace(' 23,', ' 23rd,').replace(' 31,', ' 31st,')

                    flash('Transaction successful', 'success')
                    return render_template('receipt.html', amount=formatted_amount_receipt, sender=user.first_name + ' ' + user.last_name, receiver=account_owner.first_name + ' ' + account_owner.last_name, transaction_ref=transaction_ref, session_id=session_id, bank_name='Wallet Transfer', date=formatted_date, sender_account=user.phone_number, receiver_account=account_owner.phone_number, narration=message)
                except IntegrityError as e:
                    if 'UNIQUE constraint failed' in str(e):
                        db.session.rollback()
                        continue
                    else:
                        raise e
                except Exception as e:
                    db.session.rollback()
                    flash('Transaction failed due to an error: ' + str(e), 'danger')
                    break
        else:
            flash('Incorrect transaction pin', 'danger')

    return render_template('final_wallet.html', account_owner=account_owner, amount=formatted_amount, message=message)





# Transaction receipt

@app.route('/receipt', methods=['GET', 'POST'])
@login_required
def receipt():
    from models import Receipts
    user = current_user

    if user:
        receipts = Receipts.query.filter_by(user_id=user.id).order_by(Receipts.date.desc()).first()
        

        print(receipts, "AAAAAAAAAAAAAAAAAAA")
    return render_template('receipt.html')




# View single receipt from dashboard

@app.route('/view_receipt/<int:receipt_id>', methods=['GET', 'POST'])
@login_required
def view_receipt(receipt_id):
    from models import Receipts, TransactionHistory
    receipt = TransactionHistory.query.get_or_404(receipt_id)
    print(receipt, "VVVVVVVVVVVVVVVVVVVVVV")
    return render_template('view_receipt.html', receipt=receipt)


