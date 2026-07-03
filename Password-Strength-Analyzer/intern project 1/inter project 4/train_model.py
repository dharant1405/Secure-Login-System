import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

# Create target directories if they do not exist
os.makedirs("datasets", exist_ok=True)
os.makedirs("models", exist_ok=True)

def generate_dataset():
    """
    Programmatically generates a balanced, high-entropy dataset of phishing and legitimate emails.
    """
    phishing_emails = [
        # Financial / Banking Spoofing
        "URGENT: Your bank account access has been temporarily suspended. Please click the link to verify your identity immediately: http://fakebank-verify.com/login",
        "Action Required: We detected an unauthorized login attempt on your Wells Fargo account from IP 184.23.11.9. Update credentials now: http://wellsfargo-security-check.net",
        "Notice: Your credit card payment of $1,250.00 is overdue. Avoid late penalties by submitting your payment details here: http://overdue-cards-portal.info/pay",
        "Your PayPal account is restricted. We found suspicious activities associated with your recent purchases. Verify ownership here: http://paypal-restrictions-resolve.org",
        "Incoming Wire Transfer Notice: You have a pending credit of $4,850.00 from an unknown sender. Confirm bank routing numbers to release funds: http://routing-check-gate.net",
        # Credential Harvesting / IT Support Spoofing
        "CRITICAL SECURITY ALERT: Your corporate email password expires in 24 hours. Keep your current password by verifying at: http://it-support-password-reset.com",
        "IT Helpdesk Notice: We are upgrading our email servers tonight. To prevent inbox deletion, confirm your email login and password: http://corporate-migration-port.com",
        "Microsoft Account Security: We noticed unusual activity on your Outlook account. Click here to confirm you are the owner: http://outlook-identity-verify.info",
        "Slack Security: Multi-factor authentication has been disabled for your workspace. If you did not make this change, report immediately: http://slack-security-support.org",
        "HR Notice: Annual payroll updates required. Review your direct deposit information and verify SSN on our new portal: http://hr-payroll-portal-update.net/login",
        # Urgent Corporate / Invoice Scams
        "Immediate Action: Please find attached billing invoice #889726. Confirm payment execution within 48 hours to avoid service interruption: http://invoice-portal-pdf.org",
        "From CEO: I am in a board meeting and need you to purchase 5 Google Play gift cards ($100 each) for client rewards. Send code photos to my email ASAP.",
        "Internal Audit Inquiry: You are required to review the financial report document immediately and log in to sign the NDA: http://finance-audit-nda.net",
        "Delivery Status: DHL shipment #99827 could not be delivered due to incorrect address. Pay $2.50 redirection fee here: http://dhl-package-redirection.info/pay",
        "Adobe Document Cloud: The department manager has shared an confidential document 'Salary_Review_2026.pdf' with you. Access document: http://adobe-confidential-pdf.org",
        # Lottery, Offers, and Spam Phishing
        "Congratulations! Your email address was selected as the winner of $1,000,000.00 in our annual lottery. Contact claims manager at claims@lottery-winner.info",
        "Guaranteed Inheritance Notice: A distant relative passed away leaving an estate of $4.5 Million. Claim inheritance funds: http://inheritance-estate-claim.com",
        "Earn $500/day working from home for just 2 hours! No experience required. Click here to register your application details: http://work-home-careers-hub.net",
        "Exclusive Offer: Get free access to premium streaming accounts. Enter your email and current password to start your subscription: http://free-streaming-access.org",
        "Re-activate Netflix Account: We could not process your last subscription payment. Update your credit card details immediately: http://netflix-payment-retry.com"
    ]
    
    # Expand Phishing with variations to reach 75 samples
    phishing_variations = []
    subjects = ["Update details", "Action Required", "Alert", "Security Notice", "Immediate Action Needed"]
    triggers = ["verify your account credentials", "confirm your identity", "update billing data", "check unauthorized logins"]
    links = ["http://verify-now.net", "http://secure-access-update.com", "http://login-portal-auth.info", "http://resolution-center.org"]
    
    for i in range(55):
        subject = subjects[i % len(subjects)]
        trigger = triggers[i % len(triggers)]
        link = links[i % len(links)]
        phishing_variations.append(
            f"{subject}: System administrators require you to {trigger} within 24 hours. Failure to comply leads to termination. Log in here: {link}"
        )
    phishing_emails.extend(phishing_variations)

    legitimate_emails = [
        # Internal Workplace Communication
        "Hi Team, please find attached the meeting minutes from our weekly sync. Let me know if there are any corrections or adjustments needed.",
        "Weekly status update: Sprint 4 is progressing on schedule. Please make sure all tasks on JIRA are updated by Friday 5 PM.",
        "Hi, are you available for a quick sync tomorrow at 10 AM to discuss the database migration plan? Let me know.",
        "Re: Project Planning. I have reviewed the design documentation and left several comments on the shared drive. Let's discuss on Slack.",
        "Team Lunch: We are planning a group lunch this Friday to celebrate the successful product release. Please fill out the RSVP form.",
        # Standard Transactions / Confirmations
        "Your order #489271 has been shipped. Track your shipment progress using your official DHL tracker. Estimated delivery is Friday.",
        "Thank you for your purchase from Amazon. Your payment of $42.50 was processed successfully. View invoice in your official account page.",
        "Your Zoom meeting password has been updated. If you did not request this, please change your security settings inside the portal.",
        "GitHub Notice: A new pull request #112 has been submitted for review. Please check the code changes and approve if verified.",
        "Monthly newsletter: Here are the latest articles and trends in cyber security for July 2026. Read more on our official blog.",
        # Standard Personal / Social Communication
        "Hey, are we still on for coffee this afternoon? Let me know what time works best for you.",
        "Hi Dad, I will be arriving at the airport at 6 PM tomorrow. Looking forward to catching up this weekend.",
        "Thanks for the birthday wishes! I had a great day celebrating with the family.",
        "Hi, I noticed a typo on slide 4 of the presentation slides. I'll correct it before the client meeting.",
        "Vacation Request Approved: Your time-off request for July 12 to July 16 has been approved by the manager."
    ]
    
    # Expand Legitimate with variations to reach 75 samples
    legitimate_variations = []
    senders = ["Sarah", "John", "David", "HR Department", "Project Coordinator"]
    topics = ["project updates", "meeting agenda", "feedback survey", "shared documentation", "lunch plans"]
    closings = ["Regards", "Best", "Thanks", "Have a great day", "Sincerely"]
    
    for i in range(60):
        sender = senders[i % len(senders)]
        topic = topics[i % len(topics)]
        closing = closings[i % len(closings)]
        legitimate_variations.append(
            f"Hello team, this is {sender} sending the notes regarding our {topic}. Let me know if you have any questions. {closing}."
        )
    legitimate_emails.extend(legitimate_variations)
    
    # Combine into a single DataFrame
    data = []
    for email in phishing_emails:
        data.append({"text": email, "label": 1}) # 1 = Phishing
    for email in legitimate_emails:
        data.append({"text": email, "label": 0}) # 0 = Legitimate/Safe
        
    df = pd.DataFrame(data)
    # Shuffle dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv("datasets/emails.csv", index=False)
    print(f"[+] Dataset created with {len(df)} samples (Balanced: {len(phishing_emails)} phishing, {len(legitimate_emails)} safe).")
    return df

def train_and_evaluate():
    """
    Loads dataset, trains Multinomial Naive Bayes model using TF-IDF, and evaluates results.
    """
    df = generate_dataset()
    
    # Split into features (X) and targets (y)
    X = df['text']
    y = df['label']
    
    # Split into train and test sets (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)
    
    # TF-IDF Vectorization
    vectorizer = TfidfVectorizer(stop_words='english', min_df=1, lowercase=True)
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    # Train Multinomial Naive Bayes Classifier
    classifier = MultinomialNB(alpha=1.0)
    classifier.fit(X_train_tfidf, y_train)
    
    # Predictions
    y_pred = classifier.predict(X_test_tfidf)
    
    # Evaluate
    accuracy = accuracy_score(y_test, y_pred)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')
    
    metrics = {
        "accuracy": float(accuracy),
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp)
        },
        "classification_report": {
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1)
        },
        "total_samples": int(len(df)),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test))
    }
    
    print("\n=== Model Evaluation Metrics ===")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1-Score: {f1:.4f}")
    
    # Save model and vectorizer
    joblib.dump(classifier, "models/phishing_model.pkl")
    joblib.dump(vectorizer, "models/tfidf_vectorizer.pkl")
    
    # Save evaluation stats to JSON for web application usage
    with open("models/evaluation_metrics.json", "w") as f:
        json.dump(metrics, f, indent=4)
        
    print("[+] Model files and metrics serialized successfully.")

if __name__ == "__main__":
    train_and_evaluate()
