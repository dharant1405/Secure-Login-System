import os
import uuid
import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for
from predict import PhishingDetector

app = Flask(__name__)

# Initialize the machine learning classifier and heuristics engine
detector = PhishingDetector()

# Templates dictionary for example threat simulation
SIMULATED_TEMPLATES = {
    "lottery": {
        "subject": "OFFICIAL WINNER: You won $1,000,000 Cash Prize!",
        "body": "Dear customer, your email address has been selected as the grand prize winner of $1,000,000 in our global lottery sweepstakes promotion. To transfer the funds to your banking account, click this link http://bit.ly/secure-login-392fk and verify your direct deposit and credit card details immediately. Offer expires in 24 hours.",
        "sender": "rewards@lottery-sweepstakes-int.com",
        "url": "http://bit.ly/secure-login-392fk"
    },
    "netflix": {
        "subject": "Your Netflix membership is on hold - Update payment details",
        "body": "Your subscription has failed to renew because your credit card on file was declined. To avoid service disruption and restore access to your account, please update your billing details here http://192.168.1.104/secure/netflix/update immediately. Thank you, Netflix Customer Support.",
        "sender": "billing@netflx-renew.com",
        "url": "http://192.168.1.104/secure/netflix/update"
    },
    "aws": {
        "subject": "AWS Monthly Invoice Statement #4829",
        "body": "Hi there, your monthly Amazon Web Services (AWS) bill is ready. The total charge of $150.00 has been billed to your credit card ending in 4829. You can view the full cost breakdown and download your PDF invoice in your Billing Console at https://aws.amazon.com/console.",
        "sender": "billing@aws.amazon.com",
        "url": "https://aws.amazon.com/console"
    },
    "meeting": {
        "subject": "Meeting Minutes: Product design review session",
        "body": "Hi everyone, here are the minutes from today's product design review. We decided to go ahead with the dark mode layout. Action items are assigned in Jira, let's target completing them by Wednesday. Click here to join our mentoring folder: https://meet.google.com/abc-defg-hij.",
        "sender": "pm@company.com",
        "url": "https://meet.google.com/abc-defg-hij"
    }
}

@app.route("/")
def home():
    """Renders the main dashboard index page."""
    return render_template("index.html")

@app.route("/example/<template_id>")
def get_example(template_id):
    """Returns JSON template data for form pre-filling."""
    if template_id in SIMULATED_TEMPLATES:
        return jsonify(SIMULATED_TEMPLATES[template_id])
    return jsonify({"error": "Template not found"}), 404

@app.route("/analyze", methods=["POST"])
def analyze_email():
    """
    Handles form analysis submission. Integrates both form values and
    potential file uploads, performs classification, and displays result.html.
    """
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()
    sender = request.form.get("sender", "").strip()
    url = request.form.get("url", "").strip()

    # Fallback to handle direct backend file uploads
    if 'email_file' in request.files:
        file = request.files['email_file']
        if file and file.filename.endswith('.txt'):
            try:
                content = file.read().decode('utf-8')
                # Simplistic header parsing
                lines = content.split('\n')
                file_subj, file_sender, file_url = "", "", ""
                body_lines = []
                in_headers = True
                for line in lines:
                    line_strip = line.strip()
                    if in_headers:
                        if line_strip == "":
                            in_headers = False
                            continue
                        if line_strip.lower().startswith("subject:"):
                            file_subj = line_strip[8:].strip()
                        elif line_strip.lower().startswith("from:"):
                            file_sender = line_strip[5:].strip()
                        elif line_strip.lower().startswith("url:") or line_strip.lower().startswith("link:"):
                            file_url = line_strip[4:].strip()
                    else:
                        body_lines.append(line)
                
                if file_subj: subject = file_subj
                if file_sender: sender = file_sender
                if file_url: url = file_url
                if body_lines: body = "\n".join(body_lines).strip()
            except Exception as e:
                print(f"Error decoding file upload: {e}")

    # Ensure we have at least some basic input fields filled
    if not subject and not body and not sender:
        return redirect(url_for("home"))

    # Perform analysis
    result = detector.predict(
        subject=subject,
        body=body,
        sender=sender,
        url=url
    )

    # Generate Audit Meta Data
    tx_id = f"AEGIS-{uuid.uuid4().hex[:6].upper()}-{datetime.date.today().year}"
    scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    input_data = {
        "subject": subject,
        "body": body,
        "sender": sender,
        "url": url
    }

    return render_template(
        "result.html",
        result=result,
        input_data=input_data,
        tx_id=tx_id,
        scan_date=scan_date
    )

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """API endpoint to check email JSON directly and return classifications."""
    data = request.get_json() or {}
    subject = data.get("subject", "")
    body = data.get("body", "")
    sender = data.get("sender", "")
    url = data.get("url", "")

    if not subject and not body and not sender:
        return jsonify({"error": "Missing input fields (subject, body, or sender)"}), 400

    result = detector.predict(
        subject=subject,
        body=body,
        sender=sender,
        url=url
    )
    return jsonify(result)

if __name__ == "__main__":
    # Start the server on port 5000
    app.run(host="127.0.0.1", port=5000, debug=True)
