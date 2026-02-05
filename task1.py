from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
import bcrypt

app = Flask(__name__)
app.secret_key = 'my_secret_key'

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

    # Redirect to home if already logged in
    if session.get('logged_in'):
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
    # Redirect to home if not logged in
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('loggedIn.html', name=session['user'], email=session['email'])

# Logout
@app.route('/logout')
def logout():
    # Clear the session and redirect to home
    session.clear()
    return redirect(url_for('home'))

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
        if not errors:
            check_query = "SELECT * FROM login_info WHERE email = %s"
            cursor.execute(check_query, (email,))
            if cursor.fetchone():
                errors["email"] = "Account with this email already exists. Please log in."
            elif len(password) < 6:
                errors["password"] = "Password must be at least 6 characters long."
            elif not any(char.isdigit() for char in password):
                errors["password"] = "Password must contain at least one number."
            elif not any(char.isupper() for char in password):
                errors["password"] = "Password must contain at least one uppercase letter."
            elif not any(char.islower() for char in password):
                errors["password"] = "Password must contain at least one lowercase letter."
            elif not any(char in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for char in password):
                errors["password"] = "Password must contain at least one special character."
            elif ' ' in password:
                errors["password"] = "Password must not contain spaces."
            elif fname.isdigit() or lname.isdigit():
                errors["name"] = "Names cannot contain numbers."
            elif not any("@" in email and "." in email for char in email):
                errors["email"] = "Invalid email."
            else:
                name = fname + " " + lname
                # Hash the password
                hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

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
        elif current_password != result[1]:
            errors["currentPassword"] = "Current password is incorrect."

        # Validate new password
        if not new_password:
            errors["newPassword"] = "New password is required."
        elif len(new_password) < 6:
            errors["newPassword"] = "New password must be at least 6 characters long."
        elif not any(char.isdigit() for char in new_password):
            errors["newPassword"] = "New password must contain at least one number."
        elif not any(char.isupper() for char in new_password):
            errors["newPassword"] = "New password must contain at least one uppercase letter."
        elif not any(char.islower() for char in new_password):
            errors["newPassword"] = "New password must contain at least one lowercase letter."
        elif not any(char in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~" for char in new_password):
            errors["newPassword"] = "New password must contain at least one special character."
        elif ' ' in new_password:
            errors["newPassword"] = "New password must not contain spaces."

        if confirm_password != new_password:
            errors["confirmPassword"] = "Passwords do not match."

        if not errors:
            update_query = "UPDATE login_info SET password=%s WHERE email=%s"
            cursor.execute(update_query, (new_password, email))
            conn.commit()
            return "Password changed successfully."

    return render_template("change.html", errors=errors)

if __name__ == '__main__':
    app.run(debug=True)

conn.close()
