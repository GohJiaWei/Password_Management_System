from flask_mysqldb import MySQL
from flask import Flask, render_template, request, url_for, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_login import login_user, logout_user, current_user, login_required


app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'db_passwordmanagement'

mysql = MySQL (app)

# After app = Flask(__name__)
bcrypt = Bcrypt(app)

# db = SQLAlchemy(app)
# bcrypt = Bcrypt(app)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", [user_id])
    user = cur.fetchone()
    cur.close()
    if user:
        return user
    return None



# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))


# class User(db.Model, UserMixin):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(20), nullable=False, unique=True)
#     password = db.Column(db.String(80), nullable=False)


# class RegisterForm(FlaskForm):
#     username = StringField(validators=[
#                            InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

#     password = PasswordField(validators=[
#                              InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

#     submit = SubmitField('Register')

#     def validate_username(self, username):
#         existing_user_username = User.query.filter_by(
#             username=username.data).first()
#         if existing_user_username:
#             raise ValidationError(
#                 'That username already exists. Please choose a different one.')


# class LoginForm(FlaskForm):
#     username = StringField(validators=[
#                            InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

#     password = PasswordField(validators=[
#                              InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

#     submit = SubmitField('Login')


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/education')
def education():
    return render_template('educational_resources.html')

@app.route('/strength')
def strength():
    return render_template('strength.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     form = LoginForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(username=form.username.data).first()
#         if user:
#             if bcrypt.check_password_hash(user.password, form.password.data):
#                 login_user(user)
#                 return redirect(url_for('dashboard'))
#     return render_template('login.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # submitted_name = request.form['name']
        submitted_email = request.form['email']
        submitted_password = request.form['password']  # Get the password from form
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", [submitted_email])
        user = cur.fetchone()
        cur.close()
        
        if user and bcrypt.check_password_hash(user[2], submitted_password):  # Assuming password is at index 3
            return redirect(url_for('setup_2fa'))
        else:
            error = "Login Failed. Please try again."
    
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM password_stored")
    fetchdata = cur.fetchall()
    cur.close()
    return render_template('dashboard.html', data=fetchdata)

# @app.route('/dashboard', methods=['GET', 'POST'])
# @login_required
# def dashboard():
#     return render_template('dashboard.html')


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

@app.route('/save_password', methods=['POST'])
def save_password():
    if request.method == 'POST':
        website_name = request.form['gen--website']
        email = request.form['gen--username']
        password = request.form['gen--pass']

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

        # Insert the new password entry into the database if it's strong and unique for the website/email combination
        cur.execute("INSERT INTO password_stored(website_name, email, password) VALUES(%s, %s, %s)", (website_name, email, password))
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


# @ app.route('/register', methods=['GET', 'POST'])
# def register():
#     form = RegisterForm()

#     if form.validate_on_submit():
#         hashed_password = bcrypt.generate_password_hash(form.password.data)
#         new_user = User(username=form.username.data, password=hashed_password)
#         db.session.add(new_user)
#         db.session.commit()
#         return redirect(url_for('login'))

#     return render_template('register.html', form=form)

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

from flask import Flask, render_template
import pyotp
import qrcode
from base64 import b64encode
from io import BytesIO

@app.route('/setup_2fa')
def setup_2fa():
    key = pyotp.random_base32()
    session['otp_secret'] = key  # Store the secret key in the session

    uri = pyotp.totp.TOTP(key).provisioning_uri(name="User", issuer_name="Password Management System")
    img = qrcode.make(uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = b64encode(buffered.getvalue()).decode()
    return render_template('2FA.html', img_data=img_str)


@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    user_input = request.form['token']
    otp_secret = session.get('otp_secret')

    if otp_secret is None:
        return "Session expired or OTP setup not initiated.", 403

    totp = pyotp.TOTP(otp_secret)
    if totp.verify(user_input):
        # If the token is valid, proceed to the dashboard
        return redirect(url_for('dashboard'))
    else:
        # If the token is invalid, ask the user to enter the OTP again
        # Optionally, you can pass a message to inform the user
        
        return render_template('2FA.html', error="Invalid OTP. Please try again.", img_data=None)


if __name__ == "__main__":
    app.run(debug=True)
    
# if __name__ == "__main__":
#     app.run(debug=True, port=5001)
