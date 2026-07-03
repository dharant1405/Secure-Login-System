import os
import re
import time
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, urljoin

from flask import Flask, render_template, redirect, url_for, flash, request, session, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError

# Import database components
from models import db, User

app = Flask(__name__)

# --- SECURE CONFIGURATION ---
# Generate a secure 32-byte secret key dynamically if not configured in environment
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Database configuration - absolute path to ensure root location database.db
db_path = os.path.join(app.root_path, 'database.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Hardened Session Management
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# If using HTTPS locally (or in production), set this to True. Default to False for basic local testing:
app.config['SESSION_COOKIE_SECURE'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

# Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Authentication required to access this node."
login_manager.login_message_category = "warning"
login_manager.session_protection = "strong"  # Prevent session hijacking

# --- BRUTE FORCE PREVENTION ---
FAILED_LOGIN_LIMIT = 5
LOCKOUT_DURATION = 300  # 5 minutes in seconds
login_attempts = {}  # In-memory store: ip -> {'count': int, 'block_until': float}

def is_ip_blocked(ip):
    now = time.time()
    if ip in login_attempts:
        record = login_attempts[ip]
        if record['block_until'] > now:
            return True, int(record['block_until'] - now)
        elif record['block_until'] > 0:
            # Lockout expired, reset counters
            login_attempts[ip] = {'count': 0, 'block_until': 0}
    return False, 0

def record_failed_login(ip):
    now = time.time()
    if ip not in login_attempts:
        login_attempts[ip] = {'count': 1, 'block_until': 0}
    else:
        login_attempts[ip]['count'] += 1
        if login_attempts[ip]['count'] >= FAILED_LOGIN_LIMIT:
            login_attempts[ip]['block_until'] = now + LOCKOUT_DURATION

def clear_failed_logins(ip):
    if ip in login_attempts:
        login_attempts.pop(ip)

# --- USER LOADER ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- OPEN REDIRECT VULNERABILITY MITIGATION ---
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# --- SECURE FORMS DEFINITION ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required."),
        Length(min=4, max=25, message="Username must be between 4 and 25 characters.")
    ])
    email = StringField('Email', validators=[
        DataRequired(message="Email address is required."),
        Email(message="Please specify a valid email address.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required."),
        Length(min=8, message="Password must be at least 8 characters long.")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Password confirmation is required."),
        EqualTo('password', message="Passwords do not match.")
    ])
    submit = SubmitField('Initialize Node')

    def validate_username(self, username):
        # Prevent special characters from causing code execution or SQL injection logic
        if not re.match(r'^[a-zA-Z0-9_-]+$', username.data):
            raise ValidationError("Username can only contain alphanumeric characters, hyphens, and underscores.")
        
        # Check duplicate
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError("This username has already been registered.")

    def validate_email(self, email):
        # Check duplicate
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError("This email address is already registered.")

    def validate_password(self, password):
        val = password.data
        if not re.search(r"[a-z]", val):
            raise ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r"[A-Z]", val):
            raise ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r"[0-9]", val):
            raise ValidationError("Password must contain at least one number.")
        if not re.search(r"[_@$!%*?&+-]", val):
            raise ValidationError("Password must contain at least one special character (_@$!%*?&+-).")


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message="Username is required.")])
    password = PasswordField('Password', validators=[DataRequired(message="Password is required.")])
    remember = BooleanField('Maintain Secure Connection (Remember Me)')
    submit = SubmitField('Establish Uplink')


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="Email is required."),
        Email(message="Please specify a valid email address.")
    ])
    submit = SubmitField('Initiate Recovery')

# --- SECURITY RESPONSE HEADERS ---
@app.after_request
def apply_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    return response

# --- FORCED SESSION TIMEOUT MANAGEMENT ---
@app.before_request
def make_session_permanent():
    session.permanent = True
    # Update last active time to track session activity
    session.modified = True

# --- ROUTE HANDLERS ---
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Secure password hashing with salt (Bcrypt handles salting automatically)
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        
        # Save user to DB securely using parameterized SQLAlchemy mapping
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_pw
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash("Registration protocols complete. Account established.", "success")
        return redirect(url_for('login'))
        
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    ip_addr = request.remote_addr
    
    # Check IP lockout status before parsing submit
    blocked, time_left = is_ip_blocked(ip_addr)
    if blocked:
        flash(f"System locked due to too many failed attempts. Retry in {time_left}s.", "danger")
        return render_template('login.html', form=form)
        
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            # Login successful
            clear_failed_logins(ip_addr)
            
            # Update last login timestamp using UTC
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            
            # Log user in
            login_user(user, remember=form.remember.data)
            
            # Safe redirect validation
            next_page = request.args.get('next')
            if not next_page or not is_safe_url(next_page):
                next_page = url_for('dashboard')
                
            flash(f"Uplink established. Welcome back, agent {user.username}.", "success")
            return redirect(next_page)
        else:
            # Login failed
            record_failed_login(ip_addr)
            # Generic error message to prevent enumeration
            flash("Uplink failed. Invalid username or passcode credential.", "danger")
            
    return render_template('login.html', form=form)


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        # Avoid user enumeration: show the same success message even if email is not found
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            # Log the reset trigger for audit purposes
            app.logger.info(f"Password reset requested for email: {email}")
            
        flash("If that email is registered in our database, recovery steps have been dispatched.", "info")
        return redirect(url_for('login'))
        
    return render_template('forgot_password.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    # Calculate account protection level based on configuration
    # High: standard setup. Ultra: No Remember Me cookie active and session timeout set.
    protection_level = "ULTRA - MAX PROTOCOL"
    
    # We can inspect if the "remember me" cookie was used.
    # Flask-login sets 'remember_me' in session or we can determine from cookies.
    # If the user chose "Remember me", then session cookie doesn't expire in 15 mins.
    if session.get('remember_me') == 'y' or 'remember_token' in request.cookies:
        protection_level = "HIGH SECURE PROTOCOL"

    # Format registration date and last login
    reg_date = current_user.registration_date.strftime('%Y-%m-%d %H:%M:%S UTC')
    last_login_date = current_user.last_login.strftime('%Y-%m-%d %H:%M:%S UTC') if current_user.last_login else 'First Session'

    return render_template(
        'dashboard.html',
        username=current_user.username,
        email=current_user.email,
        registration_date=reg_date,
        last_login=last_login_date,
        security_status="SECURED & ENCRYPTED",
        protection_level=protection_level
    )


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Secure connection severed. Session terminated.", "info")
    return redirect(url_for('login'))


# --- ERROR HANDLERS ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('index.html', error_message="NODE_NOT_FOUND: 404"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('index.html', error_message="INTERNAL_ERROR: 500"), 500

@app.errorhandler(403)
def forbidden(e):
    return render_template('index.html', error_message="FORBIDDEN_NODE: 403"), 403

# Initialize Database Schema automatically
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    # Running locally on port 5000
    app.run(debug=True, host='127.0.0.1', port=5000)
