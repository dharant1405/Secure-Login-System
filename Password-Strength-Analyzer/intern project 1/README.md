# Cyber Security Project: Secure Authentication Gateway

This project implements a fully functional, secure user authentication system built using Python Flask, SQLite, and Bootstrap 5. It is designed to demonstrate key defensive security principles, making it suitable for a Cyber Security internship report.

## 🔒 Security Implementations

1. **SQL Injection Mitigation (Parameterized Queries)**
   - All database interactions utilize SQLite parameterized queries (`?` place-markers). User input is bound as values and never interpreted as SQL commands.
   - Files: [user_model.py](file:///c:/Users/DHARANI%20M/OneDrive/Documents/project%20D/intern%20project/intern%20project%201/models/user_model.py)

2. **Password Hashing (Bcrypt)**
   - Uses the Blowfish-based Bcrypt hashing function with a cost factor of 12. Password hashing includes salts to resist precomputed dictionary/rainbow table attacks.
   - Files: [user_model.py](file:///c:/Users/DHARANI%20M/OneDrive/Documents/project%20D/intern%20project/intern%20project%201/models/user_model.py)

3. **Cross-Site Request Forgery (CSRF) Defense**
   - Implements a manual verification pattern checking random session tokens against hidden form parameters on all POST submissions.
   - Configures session cookies with the `SameSite=Lax` constraint.
   - Files: [app.py](file:///c:/Users/DHARANI%20M/OneDrive/Documents/project%20D/intern%20project/intern%20project%201/app.py)

4. **Hardened Session Management**
   - Cookies are locked down via `HttpOnly=True` to block script read access, preventing XSS-based cookie theft.
   - Absolute session idle timeouts are enforced (15 minutes).
   - Session identifiers are destroyed (`session.clear()`) on user login and logout.

5. **Defensive Response HTTP Headers**
   - Injects hardening headers including:
     - `Content-Security-Policy` (CSP) to restrict scripts and stylesheets to trusted CDNs.
     - `X-Frame-Options: DENY` to defend against clickjacking.
     - `X-Content-Type-Options: nosniff` to prevent MIME hijacking.

---

## 🎨 Theme & Visual Elements
- Designed around a high-fidelity **Security Operations Center (SOC)** theme.
- Features custom dark mode CSS, cyber neon cyan/pink accents, subtle grid lines, and interactive glowing card borders.
- Includes a real-time **Password Strength Check UI** that tests password complexity (letters, numbers, symbols, uppercase, length) dynamically as the user types.
- Provides a mock SQL Injection tester in the dashboard console showing secure parameterized query evaluations side-by-side with vulnerable ones.

---

## ⚙️ Running Locally

### 1. Prerequisites
Install the required packages:
```bash
pip install flask bcrypt requests
```

### 2. Database Creation
Create the SQLite schema:
```bash
python init_db.py
```

### 3. Start the Server
Launch the application:
```bash
python app.py
```
Access the dashboard at **http://127.0.0.1:5001**.
*(Port is configured to 5001 to prevent conflicts on standard local machines).*
