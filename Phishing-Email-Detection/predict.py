import os
import re
import joblib
from train_model import preprocess_text

class PhishingDetector:
    def __init__(self):
        self.model_path = os.path.join("model", "phishing_model.pkl")
        self.vectorizer_path = os.path.join("model", "vectorizer.pkl")
        
        # Self-healing: train model if files are not present
        if not os.path.exists(self.model_path) or not os.path.exists(self.vectorizer_path):
            print("Model or vectorizer not found. Starting automatic training pipeline...")
            from train_model import main as train_main
            train_main()
            
        self.model = joblib.load(self.model_path)
        self.vectorizer = joblib.load(self.vectorizer_path)

    def analyze_heuristics(self, subject, body, sender, url):
        """
        Runs structural and keyword heuristic checks to supplement the machine learning model.
        Returns a list of threat flags.
        """
        flags = []
        
        # 1. URL checks
        if url:
            url_lower = url.lower()
            # Check for IP address in URL
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
                flags.append("IP address used as URL host (typical of direct hosting scams)")
            # Check for multiple subdomains or suspicious strings
            if url_lower.count('.') > 3 and "company" not in url_lower:
                flags.append("Excessive subdomains in link address")
            # Check for high-risk words in URL
            suspicious_url_words = ['verify', 'login', 'update', 'account', 'secure', 'billing', 'signin', 'signin-paypal', 'banking', 'netflix-renew']
            for word in suspicious_url_words:
                if word in url_lower:
                    flags.append(f"Suspicious word '{word}' found in URL")
            # Check if URL uses HTTP instead of HTTPS
            if url_lower.startswith("http://"):
                flags.append("Insecure URL link (HTTP instead of HTTPS)")
                
        # 2. Sender checks
        if sender:
            sender_lower = sender.lower()
            # Free mail domain spoofing check (e.g. support@gmail.com claiming to be PayPal)
            free_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'protonmail.com']
            is_free_domain = any(domain in sender_lower for domain in free_domains)
            
            spoof_keywords = ['support', 'security', 'billing', 'admin', 'verify', 'update', 'alert']
            if is_free_domain and any(keyword in sender_lower for keyword in spoof_keywords):
                flags.append("Official-sounding username sent from a free email provider (possible phishing spoof)")
            
            # Suspicious domain structures
            if any(term in sender_lower for term in ['-security-', '-verify-', 'update-payment', 'giftcard']):
                flags.append("Sender domain contains suspicious security-themed or promo hyphenation")

        # 3. Text Body urgency checks
        body_lower = (subject + " " + body).lower()
        urgency_terms = ['urgent', 'immediately', '24 hours', '3 hours', 'expire', 'suspended', 'unauthorized login', 'action required']
        trigger_count = sum(1 for term in urgency_terms if term in body_lower)
        if trigger_count >= 2:
            flags.append("High urgency or threat-based language detected in email content")
            
        financial_lures = ['won $', 'gift card', 'cash prize', 'transfer pending', 'bitcoin wallet', 'free coupon']
        lure_count = sum(1 for term in financial_lures if term in body_lower)
        if lure_count >= 1:
            flags.append("Financial incentive/lure language detected")

        return flags

    def predict(self, subject, body, sender, url=""):
        """
        Classifies the email based on ML model + Heuristic threat analysis.
        Returns a dictionary of analysis details.
        """
        subject = subject or ""
        body = body or ""
        sender = sender or ""
        url = url or ""

        # Concatenate text features exactly as done in training
        combined_text = f"{sender} {subject} {body} {url}"
        
        # Preprocess using the identical pipeline
        processed = preprocess_text(combined_text)
        
        # Transform and predict probability
        vectorized = self.vectorizer.transform([processed])
        prob = self.model.predict_proba(vectorized)[0] # [P(Safe), P(Phishing)]
        
        # 1 = Phishing, 0 = Safe
        ml_prediction = int(self.model.predict(vectorized)[0])
        ml_confidence = float(prob[ml_prediction]) * 100
        
        # Analyze heuristics
        heuristic_flags = self.analyze_heuristics(subject, body, sender, url)
        
        # Hybrid Risk assessment
        # Even if ML says Safe, if we have multiple heuristic threat flags, upgrade risk
        if ml_prediction == 1:
            # Phishing predicted by model
            if ml_confidence >= 80 or len(heuristic_flags) >= 1:
                risk_level = "High"
                final_label = "Phishing"
            else:
                risk_level = "Medium"
                final_label = "Phishing"
        else:
            # Safe predicted by model
            if len(heuristic_flags) >= 2:
                risk_level = "Medium"
                final_label = "Phishing" # Override to Phishing if high-severity heuristics triggered
                ml_confidence = 65.0  # Adjust confidence score for overlay
            elif len(heuristic_flags) == 1:
                risk_level = "Medium"
                final_label = "Safe"
            else:
                risk_level = "Low"
                final_label = "Safe"

        # Formulate Detection Reasons
        reasons = []
        if final_label == "Phishing":
            if ml_prediction == 1:
                reasons.append("The machine learning classifier identified linguistics patterns typical of malicious or phishing campaigns.")
            else:
                reasons.append("Heuristic filters overrode the ML model due to several high-risk indicators.")
            
            for flag in heuristic_flags:
                reasons.append(f"Heuristic Flag: {flag}")
        else:
            reasons.append("The machine learning model classified this text pattern as safe with no high-risk markers.")
            if len(heuristic_flags) == 1:
                reasons.append(f"Minor indicator found but insufficient for threat alert: {heuristic_flags[0]}")
            else:
                reasons.append("No suspicious email structures, URL targets, or urgent keywords were detected.")

        # Recommendations based on results
        recommendations = []
        if final_label == "Phishing":
            recommendations = [
                "Do NOT click on any links or download any attachments contained in this email.",
                "Report this email immediately to your company's IT security team or email provider using the 'Report Phishing' button.",
                "Never reply to this message, nor enter passwords, credentials, or personal information on pages linked by it.",
                "If this claims to be from an official entity (e.g. Bank, Netflix, Boss), verify the claim by logging into their website via a separate tab, or contact them directly."
            ]
        else:
            if risk_level == "Medium":
                recommendations = [
                    "Proceed with caution. Double check the sender's actual email address for typosquatting (e.g., support@paypa1.com).",
                    "Hover over any links to check if they match the destination text before clicking.",
                    "If this email asks for payments, file transfers, or password resets, verify with the sender in person or via call."
                ]
            else:
                recommendations = [
                    "This email appears safe to read. You can interact with it normally.",
                    "Ensure your email client's security settings and filters remain up-to-date.",
                    "Always maintain a practice of cybersecurity awareness, and report anything that feels out of place."
                ]

        return {
            "prediction": final_label,
            "confidence": round(ml_confidence, 2),
            "risk_level": risk_level,
            "reasons": reasons,
            "recommendations": recommendations,
            "heuristic_count": len(heuristic_flags),
            "flags": heuristic_flags
        }

if __name__ == "__main__":
    # Quick test harness
    detector = PhishingDetector()
    sample = detector.predict(
        subject="Urgent action required for bank login",
        body="Dear customer, please click http://192.168.1.1/bank to verify your login credentials immediately.",
        sender="billing-security@chase-verify-web.net",
        url="http://192.168.1.1/bank"
    )
    print("Test prediction output:")
    print(sample)
