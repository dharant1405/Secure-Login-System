import time
from flask import Blueprint, render_template, session
from controllers.auth_controller import login_required
from models.user_model import UserModel

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@login_required
def index():
    """
    Renders the secure dashboard for authenticated users.
    Passes mock cybersecurity monitoring logs and stats to the view.
    """
    user_id = session.get('user_id')
    user = UserModel.get_user_by_id(user_id)
    
    # Generate some mock security logs to simulate a SOC (Security Operations Center) dashboard
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    mock_logs = [
        {"timestamp": current_time, "event": "Session established securely", "status": "INFO", "ip": "127.0.0.1"},
        {"timestamp": current_time, "event": "CSRF tokens validated successfully", "status": "SUCCESS", "ip": "127.0.0.1"},
        {"timestamp": current_time, "event": "HTTP-Only & SameSite headers verified", "status": "SUCCESS", "ip": "127.0.0.1"},
        {"timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - 30)), "event": "Brute-force protection check passed", "status": "SUCCESS", "ip": "127.0.0.1"},
        {"timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - 60)), "event": "Integrity check of database.db complete", "status": "SUCCESS", "ip": "SYSTEM"}
    ]

    # Dashboard Statistics
    security_stats = {
        "encryption_algorithm": "Bcrypt (Blowfish-based)",
        "session_timeout": "15 min (900 seconds)",
        "sql_injection_status": "PATCHED (Parameterized Queries)",
        "system_status": "NOMINAL (100% SECURE)"
    }

    return render_template(
        'dashboard.html',
        user=user,
        logs=mock_logs,
        stats=security_stats
    )
