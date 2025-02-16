

"""
from flask import Flask, render_template, request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)  # Initialize SQLAlchemy
bcrypt = Bcrypt(app)  # Initialize Bcrypt for password hashing

# Token generator for password reset
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# Define User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)  # Hashed password

# Create the database tables
with app.app_context():
    db.create_all()

# Function to validate university email format
def is_valid_email(email):
    return re.fullmatch(r'^[a-zA-Z0-9._%+-]+@vitbhopal\.ac\.in$', email) is not None

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Query database for user
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            return f'Welcome {user.username}'
        else:
            return 'Login failed! Invalid credentials.'

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        # Validate email format
        if not is_valid_email(email):
            return "Invalid email format! Only @vitbhopal.ac.in domain is allowed."

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return f"User {username} already exists. Please log in."

        # Hash the password before storing it
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create new user and add to database
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return f"User {username} created successfully! Welcome {username}"

    return render_template('register.html')

# Forgot Password - Request Reset Link
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            # Generate secure token
            token = serializer.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            return f"Reset password link: {reset_url}"  # Simulate sending email
        
        return "Email not found. Please try again."

    return render_template('forgot_password.html')

# Reset Password - Token Link
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Decode the token
        email = serializer.loads(token, salt='password-reset-salt', max_age=1800)
    except:
        return "Invalid or expired token."

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            return "Passwords do not match."

        # Find user by email
        user = User.query.filter_by(email=email).first()
        if user:
            # Hash the new password
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            return "Password reset successfully! You can now log in."

    return render_template('reset_password.html', token=token)  # Load the form




if __name__ == "__main__":
    app.run(debug=True)

"""



# # Forgot Password - Request Reset Link
# @app.route('/forgot-password', methods=['GET', 'POST'])
# def forgot_password():
#     if request.method == 'POST':
#         email = request.form.get('email')
#         user = User.query.filter_by(email=email).first()

#         if user:
#             # Generate secure token
#             token = serializer.dumps(email, salt='password-reset-salt')
#             reset_url = url_for('reset_password', token=token, _external=True)
#             return f"Reset password link: {reset_url}"  # Simulate sending email
        
#         return "Email not found. Please try again."

#     return render_template('forgot_password.html')

# # Reset Password - Token Link
# @app.route('/reset-password/<token>', methods=['GET', 'POST'])
# def reset_password(token):
#     try:
#         # Decode the token
#         email = serializer.loads(token, salt='password-reset-salt', max_age=1800)
#     except:
#         return "Invalid or expired token."

#     if request.method == 'POST':
#         new_password = request.form.get('new_password')
#         confirm_password = request.form.get('confirm_password')

#         if new_password != confirm_password:
#             return "Passwords do not match."

#         # Find user by email
#         user = User.query.filter_by(email=email).first()
#         if user:
#             # Hash the new password
#             hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
#             user.password = hashed_password
#             db.session.commit()
#             return "Password reset successfully! You can now log in."

#     return render_template('reset_password.html', token=token)  # Load the form





"""



from flask import Flask, render_template, request, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
import re
from flask_mail import Mail, Message  # ✅ Import Mail and Message


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
app.config['MAIL_PORT'] = 587  
app.config['MAIL_USE_TLS'] = True  
app.config['MAIL_USERNAME'] = 'lone124wolf@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'applewmjrodalkue'  # Use an app password
app.config['MAIL_DEFAULT_SENDER'] = 'lone124wolf@gmail.com'  





db = SQLAlchemy(app)  # Initialize SQLAlchemy
bcrypt = Bcrypt(app)  # Initialize Bcrypt for password hashing
mail = Mail(app)
# Token generator for password reset
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# Define User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)  # Hashed password

# Create the database tables
with app.app_context():
    db.create_all()

# Function to validate university email format
def is_valid_email(email):
    return re.fullmatch(r'^[a-zA-Z0-9._%+-]+@vitbhopal\.ac\.in$', email) is not None

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Query database for user
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            return f'Welcome {user.username}'
        else:
            return 'Login failed! Invalid credentials.'

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        # Validate email format
        if not is_valid_email(email):
            return "Invalid email format! Only @vitbhopal.ac.in domain is allowed."

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return f"User {username} already exists. Please log in."

        # Hash the password before storing it
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create new user and add to database
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return f"User {username} created successfully! Welcome {username}"

    return render_template('register.html')

# @app.route('/forgot-password', methods=['GET', 'POST'])
# def forgot_password():
#     if request.method == 'POST':
#         email = request.form.get('email')
#         user = User.query.filter_by(email=email).first()

#         if user:
#             token = serializer.dumps(user.email, salt='password-reset-salt')
#             reset_link = url_for('reset_password', token=token, _external=True)

#             # Send Email with Reset Link
#             try:
#                 msg = Message("Password Reset Request", recipients=[user.email])
#                 msg.body = f"Click the link to reset your password: {reset_link}"
#                 mail.send(msg)
#                 flash("Reset link sent! Check your email.", "success")
#             except Exception as e:
#                 flash(f"Error sending email: {str(e)}", "danger")
#                 return redirect(url_for('forgot_password'))
#         else:
#             flash("Email not found.", "danger")

#     return render_template('forgot_password.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        print(f"Received email: {email}")  # Debugging

        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(user.email, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)

            try:
                msg = Message("Password Reset Request", recipients=[user.email])
                msg.body = f"Click the link to reset your password: {reset_link}"
                mail.send(msg)
                print(f"Sent reset link to: {user.email}")  # Debugging
                flash("Reset link sent! Check your email.", "success")
            except Exception as e:
                print(f"Email sending error: {e}")  # Debugging
                flash(f"Error sending email: {str(e)}", "danger")
                return redirect(url_for('forgot_password'))
        else:
            flash("Email not found.", "danger")
        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=1800)
    except Exception as e:
        flash("Invalid or expired token.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('reset_password', token=token))

        user = User.query.filter_by(email=email).first()
        if user:
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()
            flash("Password reset successfully! You can now log in.", "success")
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/test-email')
def test_email():
    try:
        msg = Message("Test Email", recipients=["shreyas.23bcy10351@vitbhopal.ac.in"])
        msg.body = "This is a test email from Flask app."
        mail.send(msg)
        return "Test email sent successfully!"
    except Exception as e:
        return f"Error sending test email: {str(e)}"

if __name__ == "__main__":
    app.run(debug=True)


"""

from flask import Flask, render_template, request, url_for, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from itsdangerous import URLSafeTimedSerializer
import re
from flask_mail import Mail, Message  
from authlib.integrations.flask_client import OAuth  # ✅ Import OAuth

app = Flask(__name__)

# Secret Key & Config
app.config['SECRET_KEY'] = 'abcde'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
app.config['MAIL_PORT'] = 587  
app.config['MAIL_USE_TLS'] = True  
app.config['MAIL_USERNAME'] = 'abc@gmail.com'  
app.config['MAIL_PASSWORD'] = 'abcde'  
app.config['MAIL_DEFAULT_SENDER'] = 'abc@gmail.com'  

db = SQLAlchemy(app)  
bcrypt = Bcrypt(app)  
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# OAuth Setup
oauth = OAuth(app)
oauth.register(
    name='google',
   
    GOOGLE_CLIENT_ID = "your-client-id",
    GOOGLE_CLIENT_SECRET = "your-client-secret",
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/v2/auth',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'  # <-- Ensure this line is included
)


# User Model
# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     google_id = db.Column(db.String(100), unique=True, nullable=True)  # Allow Google users
#     username = db.Column(db.String(50), unique=True, nullable=True)  # Nullable for Google users
#     email = db.Column(db.String(100), unique=True, nullable=False)
#     password = db.Column(db.String(100), nullable=True)  # Nullable for Google users
#     profile_pic = db.Column(db.String(200), nullable=True)  # Store Google profile pic
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(255), unique=True, nullable=True)
    username = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=True)  # Allow NULL values for Google login
    profile_pic = db.Column(db.String(255), nullable=True)

# Create the database tables
with app.app_context():
    db.create_all()

# Function to validate university email format
def is_valid_email(email):
    return re.fullmatch(r'^[a-zA-Z0-9._%+-]+@vitbhopal\.ac\.in$', email) is not None

@app.route('/')
def home():
    return render_template('login.html')



@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.password and bcrypt.check_password_hash(user.password, password):
            session["user"] = {"name": user.username, "email": user.email}
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed! Invalid credentials or use Google login.', 'danger')

    return render_template('login.html')


# Username-Password Login
# @app.route('/login', methods=['POST', 'GET'])
# def login():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')

#         user = User.query.filter_by(username=username).first()

#         if user and bcrypt.check_password_hash(user.password, password):
#             session["user"] = {"name": user.username, "email": user.email}
#             return redirect(url_for('dashboard'))
#         else:
#             flash('Login failed! Invalid credentials.', 'danger')

#     return render_template('login.html')

# Google OAuth Login
# @app.route("/google-login")
# def google_login():
#     return oauth.google.authorize_redirect(url_for("google_callback", _external=True))
@app.route("/google-login")
def google_login():
    return oauth.google.authorize_redirect(url_for("google_callback", _external=True))

@app.route("/callback")
def google_callback():
    token = oauth.google.authorize_access_token()
    if not token:
        flash("Failed to authenticate with Google.", "danger")
        return redirect(url_for("login"))

    user_info = oauth.google.get("https://www.googleapis.com/oauth2/v3/userinfo").json()
    
    if not user_info or "email" not in user_info:
        flash("Failed to fetch user information from Google.", "danger")
        return redirect(url_for("login"))

    print(user_info)  # Debugging: Check the response from Google

    user = User.query.filter_by(email=user_info["email"]).first()

    if not user:
        new_user = User(
            google_id=user_info["sub"],
            username=user_info.get("name", "Google User"),
            email=user_info["email"],
            profile_pic=user_info.get("picture", ""),
        )
        db.session.add(new_user)
        db.session.commit()
        user = new_user  # Set user for session storage

    session["user"] = {
        "name": user.username,
        "email": user.email,
        "picture": user.profile_pic,
    }

    return redirect(url_for("dashboard"))


# Dashboard for both Auth Methods
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    user = session["user"]
    return f"""
    <h1>Welcome {user["name"]}</h1>
    <img src="{user.get("picture", '')}" alt="Profile Picture" style="width:100px"><br>
    <p>Email: {user["email"]}</p>
    <a href="/logout">Logout</a>
    """

# Logout
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        if not is_valid_email(email):
            return "Invalid email format! Only @vitbhopal.ac.in domain is allowed."

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return f"User {username} already exists. Please log in."

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return f"User {username} created successfully!"

    return render_template('register.html')

# Forgot Password
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            token = serializer.dumps(user.email, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)

            try:
                msg = Message("Password Reset Request", recipients=[user.email])
                msg.body = f"Click the link to reset your password: {reset_link}"
                mail.send(msg)
                flash("Reset link sent! Check your email.", "success")
            except Exception as e:
                flash(f"Error sending email: {str(e)}", "danger")
        else:
            flash("Email not found.", "danger")

        return redirect(url_for('forgot_password'))

    return render_template('forgot_password.html')

# Reset Password
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=1800)
    except:
        flash("Invalid or expired token.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('reset_password', token=token))

        user = User.query.filter_by(email=email).first()
        if user:
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()
            flash("Password reset successfully! You can now log in.", "success")
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# Test Email
@app.route('/test-email')
def test_email():
    try:
        msg = Message("Test Email", recipients=["shreyas.23bcy10351@vitbhopal.ac.in"])
        msg.body = "This is a test email from Flask app."
        mail.send(msg)
        return "Test email sent successfully!"
    except Exception as e:
        return f"Error sending test email: {str(e)}"

if __name__ == "__main__":
    app.run(debug=True)
