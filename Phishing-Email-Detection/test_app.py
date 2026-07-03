import os
import unittest
import json
from app import app
from predict import PhishingDetector

class PhishingDetectorTestCase(unittest.TestCase):
    def setUp(self):
        # Configure application for testing
        app.config['TESTING'] = True
        self.client = app.test_client()
        self.detector = PhishingDetector()

    def test_model_loading(self):
        """Verify that the model and vectorizer PKL files were created and load successfully."""
        self.assertIsNotNone(self.detector.model)
        self.assertIsNotNone(self.detector.vectorizer)

    def test_phishing_prediction(self):
        """Verify model accurately catches an obvious phishing example (due to keywords & heuristics)."""
        result = self.detector.predict(
            subject="Urgent: Action Required - Account Suspended",
            body="Dear user, we detected an unauthorized login to your bank account. Verify ownership here: http://bit.ly/secure-login-392fk",
            sender="billing@paypal-security-update.com",
            url="http://bit.ly/secure-login-392fk"
        )
        self.assertEqual(result["prediction"], "Phishing")
        self.assertEqual(result["risk_level"], "High")
        self.assertTrue(len(result["reasons"]) > 0)
        self.assertTrue(any("link" in r.lower() or "suspicious" in r.lower() or "model" in r.lower() for r in result["reasons"]))

    def test_safe_prediction(self):
        """Verify model classifies an obvious business email as safe."""
        result = self.detector.predict(
            subject="Weekly Project Status Update and Deliverables",
            body="Hi all, here is our weekly update. Everything is on schedule for the staging release.",
            sender="pm@company.com"
        )
        self.assertEqual(result["prediction"], "Safe")
        self.assertEqual(result["risk_level"], "Low")

    def test_home_route(self):
        """Verify home route returns the dashboard landing page."""
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Intelligent Phishing Email Classifier", response.data)
        self.assertIn(b"Threat Analysis Chamber", response.data)

    def test_example_route(self):
        """Verify template example fetching route returns the correct pre-filled values."""
        response = self.client.get('/example/lottery')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertEqual(data["sender"], "rewards@lottery-sweepstakes-int.com")
        self.assertIn("winner of $1,000,000", data["body"])

    def test_analyze_route_phishing(self):
        """Verify that submitting a phishing email form processes and returns result page with alert."""
        response = self.client.post('/analyze', data={
            'sender': 'alert@paypal-access-verify.net',
            'url': 'http://chase-bank-verify-account.net/login.php',
            'subject': 'Verify your Bank Account details within 24 hours',
            'body': 'Please verify your billing credit card details or your account will be suspended.'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"PHISHING ALERT", response.data)
        self.assertIn(b"Aegis Shield Protocols", response.data)

    def test_analyze_route_safe(self):
        """Verify that submitting a safe email form processes and returns result page with safe verdict."""
        response = self.client.post('/analyze', data={
            'sender': 'techlead@company.com',
            'url': 'https://github.com/company/project',
            'subject': 'Project Update: Weekly Sync and Deliverables',
            'body': 'Hi developers, the code reviews look good. The deployment script is merged.'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SAFE VERDICT", response.data)

    def test_api_analyze_endpoint(self):
        """Verify direct JSON API analyze route."""
        payload = {
            "sender": "rewards@lottery-sweepstakes-int.com",
            "url": "http://target-promo-voucher-claim.info",
            "subject": "Congratulations, claim your free voucher!",
            "body": "Click this link to claim your voucher."
        }
        response = self.client.post('/api/analyze', 
                                    data=json.dumps(payload), 
                                    content_type='application/json')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertEqual(data["prediction"], "Phishing")
        self.assertEqual(data["risk_level"], "High")

if __name__ == '__main__':
    unittest.main()
