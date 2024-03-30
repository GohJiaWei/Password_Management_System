from flask_mysqldb import MySQL
from flask import flash, Flask, render_template, request, url_for, redirect, session
from flask_login import login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_login import login_user, logout_user, current_user, login_required


app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'db_passwordmanagement'

mysql = MySQL (app)

bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User:
    def __init__(self, id, email):
        self.id = id
        self.email = email

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, email FROM users WHERE id = %s", [user_id])
    user_data = cur.fetchone()
    cur.close()
    if user_data:
        return User(id=user_data[0], email=user_data[1])
    return None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/education')
def education():
    return render_template('educational_resources.html')

@app.route('/strength')
def strength():
    return render_template('strength.html')


from flask_login import login_user

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        submitted_email = request.form['email']
        submitted_password = request.form['password']  # Get the password from form
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", [submitted_email])
        user = cur.fetchone()
        cur.close()
        
        # Check if user exists and password is correct
        # Assuming user[1] is email and user[2] is the hashed password
        if user and bcrypt.check_password_hash(user[2], submitted_password):
            user_obj = User(id=user[0], email=user[1])  # Create a User object
            login_user(user_obj)  # Log in the user
            return redirect(url_for('setup_2fa'))
        else:
            error = "Login Failed. Please try again."
    
    return render_template('login.html', error=error)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# Generate a key for AES-256.
aes_key = os.urandom(32)  # 32 bytes for AES-256

# Function to encrypt a password
def encrypt_password(password):
    # Ensure the data is bytes
    data = password.encode('utf-8')

    # Explicitly generate a random IV.
    iv = os.urandom(16)

    # Create an instance of Cipher using AES-256 CBC mode with the generated IV.
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())

    # Encrypt the data
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return iv + encrypted_data

# Function to decrypt a password
def decrypt_password(encrypted_password):
    # The IV is the first 16 bytes of the encrypted payload
    iv = encrypted_password[:16]
    encrypted_data = encrypted_password[16:]

    # Create an instance of Cipher using AES-256 CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())

    # Decrypt the data
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the data
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data.decode('utf-8')



@app.route('/dashboard')
def dashboard():
    user_id = current_user.get_id()
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM password_stored WHERE user_id = %s", [user_id])
    fetchdata = cur.fetchall()
    cur.close()
    
    # Decrypting the data before passing it to the template
    decrypted_data = []
    for user in fetchdata:
        decrypted_user = list(user)  # Convert tuple to list to modify it
        decrypted_user[2] = user[2]  # Assuming user[2] is the email and is not encrypted
        
        # Decrypt the password
        decrypted_user[3] = decrypt_password(user[3])  # Decrypt the password
        decrypted_data.append(decrypted_user)
        
    return render_template('dashboard.html', data=decrypted_data)

import re

def is_strong_password(password):
    if not 8 <= len(password) <= 12:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*()_+~`|}{\[\]:;?><,./-]", password):
        return False
    return True

from flask_login import current_user

@app.route('/save_password', methods=['POST'])
def save_password():
    if request.method == 'POST':
        website_name = request.form['gen--website']
        email = request.form['gen--username']
        password = request.form['gen--pass']
        user_id = current_user.get_id()  # Assuming you have the get_id method in your User class


        if not is_strong_password(password):
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM password_stored")
            fetchdata = cur.fetchall()
            cur.close()
            # Redirect with an error message
            return render_template('dashboard.html', error="Passwords must contain:<br>• a minimum of 1 lower case letter [a-z]<br>• a minimum of 1 upper case letter [A-Z]<br>• a minimum of 1 numeric character [0-9]<br>• a minimum of 1 special character: ~`!@#$%^&*()-_+={}[]|\\;:<>,./?", data=fetchdata)

        # Check if the combination of email and website name already exists
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM password_stored WHERE email = %s AND website_name = %s", (email, website_name))
        existing_entry = cur.fetchone()
        if existing_entry:
            cur = mysql.connection.cursor()
            cur.execute("SELECT * FROM password_stored")
            fetchdata = cur.fetchall()
            cur.close()
            # Provide feedback to the user that the specific combination of email and website is already used
            return render_template('dashboard.html', error="An entry for this website with the specified email already exists. Please try a different email or website name.", data=fetchdata)

        # Encrypt the password
        encrypted_password = encrypt_password(password)
        
        # Insert the new password entry into the database if it's strong and unique for the website/email combination
        cur.execute("INSERT INTO password_stored(website_name, email, password, user_id) VALUES(%s, %s, %s, %s)", (website_name, email, encrypted_password, user_id))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('dashboard'))

    return 'Method Not Allowed', 405

@app.route('/delete_password/<int:id>', methods=['POST'])
def delete_password(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM password_stored WHERE id = %s", [id])
    mysql.connection.commit()
    cur.close()
    return redirect(url_for('dashboard'))


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']  # Get password from form
        
        # Check if email already exists
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", [email])
        existing_user = cur.fetchone()
        if existing_user:
            cur.close()
            return "Email already exists. <a href='/'>Try again</a>"
        
        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Insert new user with hashed password
        cur.execute("INSERT INTO users(email, password) VALUES(%s, %s)", (email, hashed_password))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('login'))
    
    # For a GET request, render the registration form
    return render_template('register.html')  # Ensure you have a register.html template

import pyotp
import qrcode
from base64 import b64encode
from io import BytesIO

@app.route('/setup_2fa')
def setup_2fa():
    user_id = current_user.get_id()

    # Initialize cursor outside of the if/else block
    cur = mysql.connection.cursor()

    try:
        # Retrieve the user's otp_secret from the database.
        cur.execute("SELECT otp_secret,email FROM users WHERE id = %s", [user_id])
        user_data = cur.fetchone()

        if not user_data or not user_data[0]:
            # If the user does not have an otp_secret, generate and store one.
            otp_secret = pyotp.random_base32()
            # Store the otp_secret in the database for the given user_id.
            cur.execute("UPDATE users SET otp_secret = %s WHERE id = %s", (otp_secret, user_id))
            mysql.connection.commit()
        else:
            # If an otp_secret exists, use it.
            otp_secret = user_data[0]

        email = user_data[1]
        uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=f"{email}", issuer_name="Password Management System")
        img = qrcode.make(uri)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = b64encode(buffered.getvalue()).decode()
        return render_template('2FA.html', img_data=img_str)
    except Exception as e:
        mysql.connection.rollback()
        flash('Error updating OTP secret.')
        return f"Error occurred: {e}"
    finally:
        # Ensure cursor is closed after all operations
        cur.close()

@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    user_input = request.form['token']
    user_id = current_user.get_id()

    cur = mysql.connection.cursor()
    cur.execute("SELECT otp_secret FROM users WHERE id = %s", [user_id])
    user_data = cur.fetchone()
    cur.close()

    if not user_data or not user_data[0]:
        return "OTP setup not initiated.", 403

    otp_secret = user_data[0]
    totp = pyotp.TOTP(otp_secret)
    if totp.verify(user_input):
        # If the token is valid, proceed to the dashboard.
        return redirect(url_for('dashboard'))
    else:
        # If the token is invalid, ask the user to enter the OTP again.
        return render_template('2FA.html', error="Invalid OTP. Please try again.", img_data=None)

@app.route('/forget', methods=['GET', 'POST'])
def forget():
    return render_template('forget.html')


from flask import Flask,render_template,request
from flask_mail import Mail,Message
from random import randint

mail=Mail(app)

# Office 365 Email Configuration
app.config["MAIL_SERVER"] = 'smtp.office365.com'
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False  # Use TLS, not SSL with Office 365
app.config["MAIL_USERNAME"] = 'password_management@outlook.com'  # Your Office 365 email
app.config['MAIL_PASSWORD'] = 'wygqem-cuSxo4-patmot'  # Your Office 365 password

mail=Mail(app)

@app.route('/forgotpassword', methods=["GET", "POST"])
def forgotpassword():
    if request.method == "POST":
        email = request.form.get('email')
        if not email:
            return render_template('forgotpassword.html', error="Email is required.")
        
         # Check if the email exists in the database
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE email = %s", [email])
        cur.close()
        
        if result == 0:
            # Email does not exist in the database
            return render_template('forgotpassword.html', error="Email address not found in the system. Please register first.")  # Assuming you have a 'register' route for registration
        else:
            # Proceed with sending OTP
            otp = randint(100000,999999)
            msg = Message(subject='Password Management: OTP to reset your password', sender='password_management@outlook.com', recipients=[email])
            msg.body = str(otp)
            mail.send(msg)

            # Store email and otp in session
            session['email_for_password_reset'] = email
            session['otp_for_password_reset'] = str(otp)  # Convert to string for consistency

            flash('OTP has been sent to your email. Please check your email.')
            return redirect(url_for('otppassword'))

    return render_template('forgotpassword.html')


@app.route('/otppassword', methods=["GET", "POST"])
def otppassword():
    if request.method == "POST":
        user_otp = request.form.get('otp')
        session_otp = session.get('otp_for_password_reset')

        if user_otp and session_otp and user_otp == session_otp:
            return redirect(url_for('resetpassword'))
        else:
            return render_template('otppassword.html', error="Invalid OTP. Please try again.")
        
    return render_template('otppassword.html')


@app.route('/resetpassword', methods=["GET", "POST"])
def resetpassword():
    if request.method == "POST":
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            return render_template('resetpassword.html', error="Passwords do not match each other. Please enter again.")
        else:
            email = session.get('email_for_password_reset')  # Retrieve email from session
            if email is None:
                # If there's no email in the session, redirect to forgotpassword
                flash('Session expired or invalid request. Please start over.')
                return redirect(url_for('forgotpassword'))

            # Hash the new password
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

            # Update the password in the database
            cur = mysql.connection.cursor()
            cur.execute("UPDATE users SET password = %s WHERE email = %s", (hashed_password, email))
            mysql.connection.commit()
            cur.close()
            
            # Clear the email from the session
            session.pop('email_for_password_reset', None)

            flash('Your password has been updated successfully.')
            return redirect(url_for('login'))

    return render_template('resetpassword.html')

if __name__ == "__main__":
    app.run(debug=True)
