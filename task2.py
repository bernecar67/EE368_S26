from flask import Flask, render_template, request, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os
import mysql.connector
import bcrypt
import requests

load_dotenv()

app = Flask(__name__)
app.secret_key = 'my_secret_key'
salt = bcrypt.gensalt()

# Google OAuth Setup
oauth = OAuth(app)
google = oauth.register(
   name='google',
   client_id=os.getenv('CLIENT_ID'),
   client_secret=os.getenv('CLIENT_SECRET'),
   access_token_url='https://oauth2.googleapis.com/token',
   access_token_params=None,
   authorize_url='https://accounts.google.com/o/oauth2/auth',
   authorize_params=None,
   api_base_url='https://www.googleapis.com/oauth2/v2/',
   client_kwargs={'scope': 'openid email profile'},
   server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
)

try:
    # Database connection (change password as needed)
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        passwd="MySQL26!",
    )

    cursor = conn.cursor()

    # Create database (and connect to db) and table if they don't exist
    cursor.execute("CREATE DATABASE IF NOT EXISTS ee368")
    cursor.execute("USE ee368")

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_info (
        email VARCHAR(255) PRIMARY KEY UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL
    )
    """)
# Handle database connection errors
except mysql.connector.Error as err:
    print(f"Error: {err}")
    exit(1)

# Home page
@app.route('/')
def home():
    return render_template('home.html')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    errors = {}

    oauth_error = request.args.get('oauth_error')
    if oauth_error:
        errors["oauth"] = oauth_error

    print(f"testing cause yeah {errors}")
    # Redirect to home if already logged in
    if session.get('logged_in') or session.get('user') is not None:
        return redirect(url_for('home'))
    
    elif request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Pull the information from the database based on the email
        check_email = "SELECT * FROM login_info WHERE email = %s"
        cursor.execute(check_email, (email,))
        result = cursor.fetchone()

        if not result:
            if not email:
                errors["blankemail"] = "Email is required."
            else:
                errors["email"] = "here."
        else:
            if not bcrypt.checkpw(password.encode('utf-8'), result[1].encode('utf-8')):
                errors["password"] = "Incorrect password."
            else:
                name = result[2]
                # Set session variables
                session['user'] = name
                session['email'] = email
                session['logged_in'] = True
                return redirect(url_for('logged_in'))

    return render_template('login.html', errors=errors)

# Logged In Page
@app.route('/loggedIn')
def logged_in():
    user = session.get('user')

    # Redirect to home if not logged in
    if not session.get('logged_in'):
        if user:
            return render_template('loggedIn.html', name=user['name'], email=user['email'])
        else:
            return redirect(url_for('login'))
    else:
        return render_template('loggedIn.html', name=session['user'], email=session['email'])

# Google redirect to Google OAuth
@app.route('/google')
def google_redirect():
   try:
       return google.authorize_redirect(url_for('authorize', _external=True))
   except requests.exceptions.Timeout:
        return redirect(url_for('login', oauth_error="Connection timed out. Please try again."))
   except requests.exceptions.ConnectionError:
        return redirect(url_for('login', oauth_error="Connection error. Please try again."))
   except Exception as e:
       return redirect(url_for('login', oauth_error=f"Error connecting to Google. {e}"))

# Google OAuth callback
@app.route('/login/google')
def authorize():
   # Error handling for authorization process (e.g., user denies access, invalid/expired token, network issues)
   try:
       token = google.authorize_access_token()
   except Exception as e:
       print(f"Error occurred while authorizing: {e}")
       return redirect(url_for('login'))
   
   # Error handling for fetching user info (e.g., network issues, authorization errors, API changes)
   try:
       resp = google.get('userinfo')
   except Exception as e:
       print(f"Error occurred while fetching user info: {e}")
       return redirect(url_for('login'))
   
   user_info = resp.json()
   session['user'] = user_info
   return redirect('/loggedIn')

# Logout
@app.route('/logout')
def logout():
    # Clear the session and redirect to home
    session.clear()
    return redirect(url_for('home'))

# Vaidate Password Function
def validate_password(password):
    if len(password) < 6:
        return "Password must be at least 6 characters long."
    elif not any(char.isdigit() for char in password):
        return "Password must contain at least one number."
    elif not any(char.isupper() for char in password):
        return "Password must contain at least one uppercase letter."
    elif not any(char.islower() for char in password):
        return "Password must contain at least one lowercase letter."
    elif not any(char in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for char in password):
        return "Password must contain at least one special character."
    elif ' ' in password:
        return "Password must not contain spaces."
    
# Signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    errors = {}

    # Redirect to home if already logged in
    if session.get('logged_in'):
        return redirect(url_for('home'))
    
    elif request.method == 'POST':
        fname = request.form['fname']
        lname = request.form['lname']
        email = request.form['email']
        password = request.form['password']
        
        # Required fields
        if not fname:
            errors["fname"] = "First name is required."
        if not lname:
            errors["lname"] = "Last name is required."
        if not email:
            errors["email"] = "Email is required."
        if not password:
            errors["password"] = "Password is required."

        # Password, name, and email requirements
        passwordErrors = validate_password(password)
        if passwordErrors:
            errors["password"] = passwordErrors

        if not errors:
            check_query = "SELECT * FROM login_info WHERE email = %s"
            cursor.execute(check_query, (email,))
            if cursor.fetchone():
                errors["email"] = "Account with this email already exists. Please log in."
            elif errors.get("password"):
                pass
            elif fname.isdigit() or lname.isdigit():
                errors["name"] = "Names cannot contain numbers."
            elif not any("@" in email and "." in email for char in email):
                errors["email"] = "Invalid email."
            else:
                name = fname + " " + lname
                # Hash the password
                hashed_pw = bcrypt.hashpw(password.encode('utf-8'), salt)

                insert_query = "INSERT INTO login_info (email, password, name) VALUES (%s ,%s, %s)"
                cursor.execute(insert_query, (email, hashed_pw, name))
                conn.commit()

                session['user'] = name
                session['email'] = email
                session['logged_in'] = True
                return redirect(url_for('logged_in'))

    return render_template('signup.html', errors=errors)

# Change Password page
@app.route("/change", methods=['GET', 'POST'])
def change_page():
    errors = {}

    if request.method == 'POST':
        email = request.form['email']
        current_password = request.form['currentPassword']
        new_password = request.form['newPassword']
        confirm_password = request.form['confirmPassword']
        
        check_query = "SELECT * FROM login_info WHERE email = %s"
        cursor.execute(check_query, (email,))
        result = cursor.fetchone()
    
        if not result:
            errors["email"] = "User not found."
        elif not bcrypt.checkpw(current_password.encode('utf-8'), result[1].encode('utf-8')):
            errors["currentPassword"] = "Current password is incorrect."

        # Validate new password
        newPasswordErrors = validate_password(new_password)
        if newPasswordErrors:
            errors["newPassword"] = newPasswordErrors

        if confirm_password != new_password:
            errors["confirmPassword"] = "Passwords do not match."

        if not errors:
            hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), salt)
            update_query = "UPDATE login_info SET password=%s WHERE email=%s"
            cursor.execute(update_query, (hashed_pw, email))
            conn.commit()
            return redirect(url_for('home'))

    return render_template("change.html", errors=errors)

if __name__ == '__main__':
    app.run(debug=True)

conn.close()
