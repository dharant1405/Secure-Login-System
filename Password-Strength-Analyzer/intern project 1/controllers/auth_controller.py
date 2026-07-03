import re
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models.user_model import UserModel

auth_bp = Blueprint('auth', __name__)

def login_required(f):
    """
    Decorator to protect routes from unauthorized access.
    Checks if 'user_id' is stored in the active session.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # Flashing custom alert matching cyber security context
            flash("ACCESS DENIED: Authentication required. Please log in.", "danger")
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def validate_password_strength(password):
    """
    Validates password complexity.
    Requirements: Minimum 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char.
    Returns: (bool, list of error messages)
    """
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"\d", password):
        errors.append("Password must contain at least one digit.")
    if not re.search(r"[@$!%*?&#^()_+={}\[\]|\\:;\"'<>,.?/~`-]", password):
        errors.append("Password must contain at least one special character.")
    
    return len(errors) == 0, errors

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Handles secure user registration."""
    # Redirect to dashboard if user is already logged in
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Server-side validation
        if not username or not email or not password or not confirm_password:
            flash("All fields are required.", "danger")
            return render_template('register.html', username=username, email=email)

        # Username validation: alphanumeric + underscores, length 4 to 20
        if not re.match(r"^[a-zA-Z0-9_]{4,20}$", username):
            flash("Username must be 4-20 characters long and contain only letters, numbers, or underscores.", "danger")
            return render_template('register.html', username=username, email=email)

        # Email validation
        email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(email_regex, email):
            flash("Invalid email address format.", "danger")
            return render_template('register.html', username=username, email=email)

        # Password confirmation check
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html', username=username, email=email)

        # Password strength validation
        is_strong, pwd_errors = validate_password_strength(password)
        if not is_strong:
            for err in pwd_errors:
                flash(err, "danger")
            return render_template('register.html', username=username, email=email)

        # Check if username or email already exists
        if UserModel.get_user_by_username(username):
            flash("Username is already registered. Please choose another.", "danger")
            return render_template('register.html', username=username, email=email)

        if UserModel.get_user_by_email(email):
            flash("Email is already registered. Please use another or log in.", "danger")
            return render_template('register.html', username=username, email=email)

        # Create user
        if UserModel.create_user(username, email, password):
            flash("Registration successful! Access granted. Please log in.", "success")
            return redirect(url_for('auth.login'))
        else:
            flash("An error occurred during registration. Please try again.", "danger")
            return render_template('register.html', username=username, email=email)

    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handles secure user authentication and login."""
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))

    if request.method == 'POST':
        # Retrieve and sanitize input (strip whitespaces)
        username_or_email = request.form.get('username_or_email', '').strip()
        password = request.form.get('password', '')

        if not username_or_email or not password:
            flash("Please enter both username/email and password.", "danger")
            return render_template('login.html')

        # Check for user by either username or email securely
        user = None
        if '@' in username_or_email:
            user = UserModel.get_user_by_email(username_or_email)
        else:
            user = UserModel.get_user_by_username(username_or_email)

        # Verify password (using constant-time comparison to mitigate timing attacks)
        if user and UserModel.verify_password(password, user['password_hash']):
            # Security Rule: Regenerate session ID on login to protect against Session Fixation.
            # In Flask, clearing the session dictionary resets the session token.
            session.clear()
            
            # Populate session variables
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            
            # Configure Flask session to be temporary and respect config timeout (PERMANENT_SESSION_LIFETIME)
            session.permanent = True

            flash(f"Welcome back, Agent {user['username']}. Session established securely.", "success")
            return redirect(url_for('dashboard.index'))
        else:
            # Security Rule: Do NOT reveal whether the username or password was incorrect.
            # Generic error message prevents username enumeration attacks.
            flash("Invalid username/email or password.", "danger")
            return render_template('login.html', username_or_email=username_or_email)

    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    """Destroys session and logs user out."""
    session.clear()
    flash("Session terminated successfully. You have logged out.", "success")
    return redirect(url_for('auth.login'))
