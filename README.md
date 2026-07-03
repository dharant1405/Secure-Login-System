<<<<<<< HEAD
# Secure Login System (Flask)

A secure authentication system built with Python Flask, SQLite, and Bootstrap 5, featuring a cyber security theme, glassmorphic layout, and custom security configurations.

## Features

1. **User Authentication**:
   - User Registration (with real-time credentials policy check).
   - User Login (supporting both Username and Email credentials).
   - User Logout (complete session invalidation).
   - Protected Dashboard showing custom user records and session analytics.

2. **Cyber Security Implementation**:
   - **Password Cryptography**: Salted password hashing via Bcrypt.
   - **SQL Injection Prevention**: Built with SQLAlchemy ORM which handles parameterized queries automatically.
   - **CSRF Defense**: Custom session token validation on all POST actions.
   - **Session Security**: Invalidation of old session IDs on login (Session Fixation protection) + HTTPOnly and SameSite cookie options.
   - **Security Headers**: Custom HTTP headers added (`X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, and `Content-Security-Policy`).
   - **Form Validations**: Advanced password complexity checking (minimum length, casing, numbers, and special symbols) and email format regex.

3. **Visual & Interactive Design**:
   - Responsive Glassmorphism cards using Backdrop Filters and subtle translucent borders.
   - Dark space cyber security design theme.
   - HTML5 Canvas background drawing a dynamic interactive node grid.
   - Original minimalist anime-style cyber hacker avatar.
   - Custom floating inputs, password visibility toggles, and automatic alert dismissal.

---

## Folder Structure

```
Secure-Login-System/
│
├── app.py
├── models.py
├── requirements.txt
├── README.md
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│
├── static/
│   ├── css/style.css
│   ├── js/script.js
│   ├── images/
│   │   └── hacker.jpg
│
└── screenshots/
```

---

## Installation & Launch Instructions

### Prerequisites
- Python 3.8 or higher.
- `pip` package manager.

### 1. Clone/Open Project Directory
Ensure you are inside the directory:
```bash
cd "c:\Users\DHARANI M\OneDrive\Apps\intern4"
```

### 2. Setup Virtual Environment (Recommended)
```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python app.py
```

### 5. Access the Web Application
Open your browser and navigate to:
```
http://127.0.0.1:5000
```
=======
# Cyber-Security-Internship-Projects
Four Cyber Security projects developed during my internship at Thiranex IT Solutions.
>>>>>>> 0918b1cf13c8c78c9991806d5766f952ee736c5e
