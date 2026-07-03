import secrets
from flask import Flask, redirect, url_for, session, request, abort, render_template_string
from config import Config
from controllers.auth_controller import auth_bp
from controllers.dashboard_controller import dashboard_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Register controllers (Blueprints)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    # Root route - Redirects to dashboard (which handles login requirements)
    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect(url_for('dashboard.index'))
        return redirect(url_for('auth.login'))

    # Context processor to inject CSRF token into all templates
    @app.context_processor
    def inject_csrf_token():
        """
        Generates and injects a cryptographically secure CSRF token 
        into the active session and renders it in templates.
        """
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        return dict(csrf_token=session['csrf_token'])

    # Before request hook to validate CSRF tokens
    @app.before_request
    def validate_csrf():
        """
        Interceptors all incoming POST requests and validates CSRF token parameter
        against the token stored in the user session.
        """
        if request.method == "POST":
            # For JSON requests, tokens could be sent via headers. 
            # In our system, all submissions are standard HTML form POSTs.
            token = request.form.get('csrf_token')
            session_token = session.get('csrf_token')

            if not token or token != session_token:
                # CSRF validation failed - block the execution immediately
                abort(403)

    # Security Headers Hook
    @app.after_request
    def add_security_headers(response):
        """
        Injects security hardening HTTP headers into every response.
        This forms a vital part of a cyber security defense-in-depth strategy.
        """
        # Mitigates Cross-Site Scripting (XSS) and data injection attacks by limiting trusted sources.
        # Allows self, Bootstrap CDN, Google Fonts.
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "frame-ancestors 'none';"
        )
        response.headers['Content-Security-Policy'] = csp_policy
        
        # Prevents the browser from rendering the page inside a frame/iframe (Mitigates Clickjacking).
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Prevents browsers from guessing (MIME-sniffing) the MIME type, forcing them to respect the declared Content-Type.
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Instructs browsers to omit the Referer header when navigating to other domains.
        response.headers['Referrer-Policy'] = 'no-referrer'
        
        # Restricts access to sensitive browser features (camera, microphone, geolocation).
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        
        # Enable Browser XSS Protection Filter
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        return response

    # Error Handlers
    @app.errorhandler(403)
    def csrf_forbidden(e):
        return render_template_error("ERROR 403: CSRF SECURITY BREACH", "Cross-Site Request Forgery validation failed. The action was blocked for safety."), 403

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template_error("ERROR 404: RESOURCE NOT FOUND", "The requested endpoint does not exist on this server."), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template_error("ERROR 500: INTERNAL SYSTEM BREACH", "An unexpected failure occurred within the application core."), 500

    def render_template_error(title, message):
        """Helper to render a cyber-security themed fallback error message."""
        return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{{ title }}</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                body {
                    background-color: #0b0f19;
                    color: #00ffcc;
                    font-family: 'Courier New', Courier, monospace;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    text-align: center;
                }
                .error-container {
                    border: 1px solid #ff3366;
                    box-shadow: 0 0 15px rgba(255, 51, 102, 0.4);
                    background-color: rgba(11, 15, 25, 0.95);
                    padding: 30px;
                    border-radius: 8px;
                    max-width: 500px;
                }
                h1 {
                    color: #ff3366;
                    font-size: 1.8rem;
                    margin-bottom: 20px;
                }
                p {
                    color: #a0aec0;
                    font-size: 1rem;
                }
                .btn-cyber {
                    background-color: transparent;
                    border: 1px solid #00ffcc;
                    color: #00ffcc;
                    margin-top: 20px;
                    transition: all 0.3s;
                }
                .btn-cyber:hover {
                    background-color: #00ffcc;
                    color: #0b0f19;
                    box-shadow: 0 0 10px #00ffcc;
                }
            </style>
        </head>
        <body>
            <div class="error-container">
                <h1>{{ title }}</h1>
                <p>{{ message }}</p>
                <a href="/" class="btn btn-cyber">Return to Gateway</a>
            </div>
        </body>
        </html>
        """, title=title, message=message)

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5001)
