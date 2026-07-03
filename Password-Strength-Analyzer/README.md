# SHIELD // Password Strength Analyzer & Security Dashboard

A responsive, high-performance, and cybersecurity-themed web application designed to evaluate password strength using mathematical entropy, character composition rules, and real-time credential breach analysis.

This application is built for **final-year internship submissions**, demonstrating standard full-stack web development principles (Python/Flask backend and HTML/CSS/JS frontend) alongside core information security topics (Shannon Entropy, cryptographic security, and API integration).

---

## 🛠️ Tech Stack & Architecture

- **Backend Framework**: Python (Flask)
- **Security & Entropy Calculations**: Standard library cryptography principles and Shannon Entropy formula.
- **Vulnerability Data**: Integrates securely with the **Have I Been Pwned API** using **k-Anonymity** to preserve user privacy.
- **Frontend Core**: HTML5, Vanilla CSS3 (Custom Dark/Neon Cyber Design System)
- **Responsive Layout**: Bootstrap 5 grid layout and custom responsive components
- **Frontend Interactivity**: Pure JavaScript (ES6) with debounced input handlers to prevent API rate-limiting.

---

## 🚀 Key Features

1. **Real-time Diagnostic Interface**: Checks criteria (length, letters, digits, symbols) instantly on keypress.
2. **Entropy Calculator (Academic depth)**:
   - *Pool-based Entropy*: Evaluates total bit complexity based on possible combinations $E = N \log_2(R)$.
   - *Shannon Entropy*: Calculates character distribution randomness, identifying weak pattern repeating passwords (e.g. `aaaaaa`).
3. **Privacy-Preserving Breach Check**: Checks SHA-1 prefixes against over 800+ million leaked credentials without exposing the actual password.
4. **Actionable Suggestions Panel**: Highlights specific actions the user can take to fortify their passphrase.
5. **Secure Cryptographic Password Generator**: Leverages the cryptographically secure pseudo-random number generator (CSPRNG) via Python's `secrets` module.
6. **Modern Cybersecurity UI**: Sleek glassmorphism theme, glowing neon accents, and interactive responsive layout.

---

## 📁 Project Structure

```
intern project/
├── app.py                  # Flask backend containing analysis and generator APIs
├── requirements.txt        # Backend dependencies
├── README.md               # Setup instructions and documentation
├── static/
│   ├── css/
│   │   └── style.css       # Custom cyber-themed styles and neon transitions
│   └── js/
│       └── main.js         # Client-side input handlers, debouncing, and API fetches
└── templates/
    └── index.html          # Core single-page web dashboard
```

---

## ⚙️ Installation & Running Guide

Ensure you have **Python 3.8+** installed on your system.

### Step 1: Open PowerShell or Command Prompt
Navigate to the root directory of the project:
```bash
cd "c:\Users\DHARANI M\OneDrive\Documents\project D\intern project"
```

### Step 2: Create a Virtual Environment (Recommended)
This isolates the project dependencies from your system's global Python environment:
```bash
python -m venv venv
```

### Step 3: Activate the Virtual Environment
- **On Windows (PowerShell)**:
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```
- **On Windows (CMD)**:
  ```cmd
  .\venv\Scripts\activate.bat
  ```

### Step 4: Install Dependencies
Install Flask and the other required packages:
```bash
pip install -r requirements.txt
```

### Step 5: Start the Flask Application
Run the main server application:
```bash
python app.py
```

### Step 6: View the Web App
Open your browser and navigate to:
[http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🔒 Security Note (k-Anonymity Breach Check)
This application queries the **Have I Been Pwned** database using a highly secure method called **k-Anonymity**:
1. The password is hashed using SHA-1 locally: `password` -> `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`
2. Only the first **5 characters** (`5BAA6`) are sent to the HIBP API.
3. The API returns all known leaked hashes starting with `5BAA6` along with their frequency.
4. The backend checks if the remainder of the hash (`1E4C9B93F3F0682250B6CF8331B7EE68FD8`) is in the returned list.
5. The full password **never** leaves your local machine.

---

## 🎓 Internship Project Presentation Tips
When presenting this project to your internship evaluators, highlight:
- The separation of concerns between backend (cryptographic rules, API calls, random selection) and frontend (animations, responsive structure, input responsiveness).
- **Shannon Entropy vs. Pool Entropy**: Explain that Pool Entropy assumes a random uniform distribution, while Shannon Entropy analyzes the actual randomness of the text itself.
- **k-Anonymity privacy model**: Explain how you securely checked for leaks without sharing credentials.
