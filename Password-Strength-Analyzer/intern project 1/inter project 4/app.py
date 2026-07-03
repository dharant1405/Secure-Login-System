import os
import json
import re
import joblib
from flask import Flask, render_template, request, jsonify, abort

# Set up absolute path references
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "models", "tfidf_vectorizer.pkl")
METRICS_PATH = os.path.join(BASE_DIR, "models", "evaluation_metrics.json")

# Initialize Flask app
app = Flask(__name__)

# Load serialized model, vectorizer, and metrics on startup
try:
    classifier = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    with open(METRICS_PATH, "r") as f:
        evaluation_metrics = json.load(f)
    print("[+] Machine learning model & TF-IDF vectorizer loaded successfully.")
except Exception as e:
    print(f"[!] Error loading model artifacts: {e}")
    print("[!] Ensure you run 'train_model.py' to generate model artifacts first.")
    evaluation_metrics = {
        "accuracy": 0.0,
        "confusion_matrix": {"tn": 0, "fp": 0, "fn": 0, "tp": 0},
        "classification_report": {"precision": 0.0, "recall": 0.0, "f1_score": 0.0},
        "total_samples": 0, "train_samples": 0, "test_samples": 0
    }

# High-risk keywords to flag as indicator hints for UI rendering
SUSPICIOUS_KEYWORDS = [
    r'urgent', r'action required', r'suspended', r'verify', r'unauthorized', 
    r'click here', r'login', r'password', r'routing number', r'social security', 
    r'ssn', r'wire transfer', r'paypal', r'restricted', r'overdue', 
    r'gift card', r'inheritance', r'winner', r'claims', r'billing', 
    r'immediate action', r'credentials', r'bank account', r'update details', 
    r'confidential', r'pay\s+\$', r'invoice'
]

@app.route('/')
def index():
    """
    Renders main dashboard page passing trained metrics.
    """
    return render_template('index.html', metrics=evaluation_metrics)

@app.route('/predict', methods=['POST'])
def predict():
    """
    Accepts JSON raw email text, tokenizes, runs TF-IDF prediction, and returns metadata.
    """
    data = request.get_json()
    if not data or 'email_text' not in data:
        return jsonify({"error": "No email text payload supplied."}), 400
        
    email_text = data['email_text'].strip()
    if not email_text:
        return jsonify({"error": "Empty text payload."}), 400
        
    # TF-IDF Feature Extraction
    features = vectorizer.transform([email_text])
    
    # Run Prediction (0 = Safe, 1 = Phishing)
    prediction = int(classifier.predict(features)[0])
    
    # Calculate Prediction Probabilities
    probabilities = classifier.predict_proba(features)[0]
    confidence = float(probabilities[prediction])
    
    # Scan for matched keywords to highlight
    matched_indicators = []
    for pattern in SUSPICIOUS_KEYWORDS:
        matches = re.findall(pattern, email_text, re.IGNORECASE)
        for match in matches:
            if match.strip() and match not in matched_indicators:
                matched_indicators.append(match)
                
    # Define custom response recommendations based on classification
    recommendations = []
    if prediction == 1:
        recommendations = [
            {
                "title": "Do Not Select Hyperlinks",
                "description": "This email is classified as a Phishing attempt. Avoid clicking links, downloading attachments, or scanning QR codes."
            },
            {
                "title": "Inspect Sender Domain Names",
                "description": "Double check the sender's full email address. Look for look-alike characters (typosquatting) or subdomains trying to mimic legitimate companies."
            },
            {
                "title": "Report and Delete Access Keys",
                "description": "Submit a notification ticket to your corporate IT security division, block the sender profile, and permanently purge the email from your trash folder."
            }
        ]
    else:
        recommendations = [
            {
                "title": "Verify Offline Request Authenticity",
                "description": "Even though this text lacks typical social engineering cues, check the sender directly if they request money transfers or internal corporate changes."
            },
            {
                "title": "Enable Multifactor Authentication (MFA)",
                "description": "Enhance account resilience by enabling MFA keys. This renders credentials useless if phishing harvesting campaigns manage to capture login tokens."
            }
        ]
        
    return jsonify({
        "prediction": prediction,
        "confidence": confidence,
        "indicators": matched_indicators,
        "recommendations": recommendations
    })

@app.after_request
def inject_security_headers(response):
    """
    HTTP Response Interceptor.
    Enforces hardening security headers globally on all outgoing traffic.
    """
    csp = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    return response

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
