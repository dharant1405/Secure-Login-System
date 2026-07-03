# Secure Login System (Cyber-Anime Theme)

A premium, industry-grade authentication system built with **Python Flask** and **SQLite**, wrapped in a futuristic cyberpunk anime-inspired HUD user interface. This project exhibits standard security controls and defense-in-depth methodologies.

---

## 🚀 Project Overview

The **Secure Login System** is designed to demonstrate robust backend verification coupled with premium visual aesthetics. The interface is optimized with a glassmorphism theme, dynamic canvas-based matrix rain/particle elements, and custom-generated cyber security anime illustrations. The system features database parameterized queries, strong security response headers, brute-force rate-limiting defenses, and robust input sanitization.

---

## 🛡️ Cyber Security Features

This application implements several core security components matching modern security engineering criteria:

1. **Secure Cryptographic Hashing**: Passwords are secure salted-hashed using the industry-proven **Bcrypt** algorithm via `Flask-Bcrypt`.
2. **Anti-SQL Injection (SQLi)**: All database interactions utilize the **SQLAlchemy ORM**, which enforces parameterized SQL queries.
3. **Session Hijacking Mitigation**: Employs Flask-Login's strong session protection, cookie `HttpOnly` and `SameSite` flags, and dynamically rotates identifiers.
4. **Brute Force & Rate Limit Protection**: Locks down IP addresses dynamically for 5 minutes after 5 consecutive failed access handshakes.
5. **Cross-Site Request Forgery (CSRF)**: Guarded by `Flask-WTF`'s cryptographic tokens injected into every transaction.
6. **Cross-Site Scripting (XSS) Mitigation**: Response filters enforce a strict **Content Security Policy (CSP)** block, alongside sanitization of incoming text inputs.
7. **Clickjacking Defense**: Explicitly emits `X-Frame-Options: DENY` on every route.
8. **Account Enumeration Defense**: Forgot Password recovery systems utilize generic responses ("If this email is registered, recovery steps have been dispatched") to prevent scraping registered user lists.
9. **Rigid Schema Validation**: Implements regex verification on user handles, syntactic email validity (RFC 5322), and multi-tier complexity checking on passwords.

---

## 🛠️ Technologies Used

### Backend
- **Python 3**
- **Flask Framework**
- **Flask-Login** (Session administration)
- **Flask-SQLAlchemy** (Database mapping layer)
- **Flask-Bcrypt** (Salted password hashing)
- **Flask-WTF** (CSRF security forms)
- **WTForms & Email Validator** (Schema enforcement)

### Frontend
- **HTML5 & Vanilla CSS3** (Custom layouts, glassmorphic filters, cybergrid grids)
- **JavaScript ES6** (Matrix rain canvas, interactive password strength indicators, loader screens, typed terminals)
- **Bootstrap 5** (Flexible grid layouts)
- **FontAwesome 6** (Cybernetic vector icons)

### Database
- **SQLite3**

---

## 📂 Folder Structure

```text
Secure-Login-System/
├── app.py                   # Main Flask routes, forms, brute-force & CSP filters
├── models.py                # Database SQLAlchemy schemas
├── requirements.txt         # Package dependencies
├── README.md                # System documentation
├── database.db              # SQLite Database (Automatically initialized on startup)
├── static/
│   ├── css/
│   │   └── style.css        # Cyber glassmorphic theme styling & grid animations
│   ├── js/
│   │   └── script.js        # Canvas, typing terminal, and password meter controllers
│   └── images/
│       ├── cyber_hacker.jpg # AI Generated Cyber Hacker Illustration
│       └── cyberpunk_bg.jpg # AI Generated Cyberpunk City Scenery
└── templates/
    ├── index.html           # Landing page gateway terminal
    ├── login.html           # Secure access interface
    ├── register.html        # User credential configuration dashboard
    ├── forgot_password.html # Recover credential portal
    └── dashboard.html       # Secured internal system information monitor
```

---

## 💻 Installation & Execution

### Prerequisites
- Python 3.8 or above installed on your system.

### Step 1: Clone or open the workspace directory
Navigate to the directory of the Secure Login System.

### Step 2: Install dependencies
Install the required python libraries using pip:
```bash
pip install -r requirements.txt
```

### Step 3: Run the application
Start the local server:
```bash
python app.py
```

The system will start up locally. By default, it will automatically initialize the database schema in `database.db` and bind to:
**`http://127.0.0.1:5000`**

---

## 🔮 Future Scope
- **Multi-Factor Authentication (MFA)**: Integrate TOTP (Time-Based One-Time Password) protocols via Google Authenticator.
- **Persistent IP Lockout Logs**: Shift brute-force lockout storage from in-memory dictionary maps to persistent DB audits.
- **OAuth2 Integration**: Allow authentication via secure third-party cyber gateways.
