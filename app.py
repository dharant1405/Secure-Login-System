import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_bcrypt import Bcrypt
from models import db, User

app = Flask(__name__)

# Security Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_login.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session Security Policies
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# In a real environment, you should use SESSION_COOKIE_SECURE = True (requires HTTPS)

# Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app)

# Create database tables
with app.app_context():
    db.create_all()

# Security Headers Hook
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net;"
    return response

# Custom CSRF Protection
@app.context_processor
def inject_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return dict(csrf_token=session['csrf_token'])

@app.before_request
def csrf_protect():
    # Only protect POST requests
    if request.method == "POST":
        # Disable CSRF check for testing if needed, but keeping it active for absolute security
        token = request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            abort(400, description="CSRF token validation failed.")

# Authentication Decorator
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation checks
        if not username or not email or not password or not confirm_password:
            flash("All fields are required.", "danger")
            return render_template('register.html')
            
        # Username validation: 4-30 chars, alphanumeric or underscores
        if not (4 <= len(username) <= 30) or not re.match(r'^\w+$', username):
            flash("Username must be between 4 and 30 characters and contain only letters, numbers, or underscores.", "danger")
            return render_template('register.html')
            
        # Email validation
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, email):
            flash("Please enter a valid email address.", "danger")
            return render_template('register.html')
            
        # Password strength validation: min 8 chars, 1 upper, 1 lower, 1 digit, 1 special char
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template('register.html')
        if not re.search(r'[A-Z]', password):
            flash("Password must contain at least one uppercase letter.", "danger")
            return render_template('register.html')
        if not re.search(r'[a-z]', password):
            flash("Password must contain at least one lowercase letter.", "danger")
            return render_template('register.html')
        if not re.search(r'[0-9]', password):
            flash("Password must contain at least one digit.", "danger")
            return render_template('register.html')
        if not re.search(r'[^A-Za-z0-9]', password):
            flash("Password must contain at least one special character.", "danger")
            return render_template('register.html')
            
        # Password confirmation
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html')
            
        # Check if user already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            # We explicitly check and inform which attribute is already taken to guide the user,
            # but in strict settings, generic responses are preferred. Let's balance usability and security:
            if existing_user.username == username:
                flash("Username is already taken.", "danger")
            else:
                flash("Email is already registered.", "danger")
            return render_template('register.html')
            
        # Hash password and save new user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred during registration. Please try again.", "danger")
            return render_template('register.html')
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        login_id = request.form.get('login_id', '').strip()  # can be username or email
        password = request.form.get('password', '')
        
        if not login_id or not password:
            flash("Please enter both username/email and password.", "danger")
            return render_template('login.html')
            
        # Search user by username or email
        user = User.query.filter((User.username == login_id) | (User.email == login_id)).first()
        
        # Verify user and password hash
        if user and bcrypt.check_password_hash(user.password, password):
            # Session Fixation protection
            session.clear()
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            # Secure generic error message
            flash("Invalid credentials. Please try again.", "danger")
            return render_template('login.html')
            
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
        
    # Render dashboard details
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been successfully logged out.", "success")
    return redirect(url_for('index'))

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5001))
    app.run(debug=True, port=port)
