import unittest
import os
import json
import joblib
from app import app, MODEL_PATH, VECTORIZER_PATH

class TestPhishingDetector(unittest.TestCase):
    def setUp(self):
        """
        Setup test client.
        """
        app.config['TESTING'] = True
        self.client = app.test_client()

    def test_model_files_exist(self):
        """
        Verify that the model, vectorizer, and metrics JSON files exist.
        """
        self.assertTrue(os.path.exists(MODEL_PATH), "Model pickle file is missing.")
        self.assertTrue(os.path.exists(VECTORIZER_PATH), "Vectorizer pickle file is missing.")

    def test_dashboard_renders(self):
        """
        Test that root route loads and renders accuracy metric correctly.
        """
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'MODEL ACCURACY SCORE', response.data)
        self.assertIn(b'Confusion Matrix', response.data)

    def test_phishing_prediction_api(self):
        """
        Test that the API endpoint successfully identifies phishing emails.
        """
        payload = {
            "email_text": "URGENT: Your Wells Fargo bank credentials have been compromised. Click here immediately to verify account and avoid card lockout."
        }
        
        response = self.client.post('/predict', 
                                    data=json.dumps(payload), 
                                    content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        self.assertEqual(data['prediction'], 1, "Failed to classify phishing text correctly.")
        self.assertTrue(data['confidence'] > 0.5, "Confidence score is too low.")
        self.assertIn("verify", data['indicators'], "Failed to extract matching indicator phrase.")
        self.assertTrue(len(data['recommendations']) > 0, "No recommendations returned.")

    def test_safe_prediction_api(self):
        """
        Test that the API endpoint successfully identifies legitimate emails.
        """
        payload = {
            "email_text": "Hello Sarah, please find the notes from our weekly team meeting. Let me know if you have any questions."
        }
        
        response = self.client.post('/predict', 
                                    data=json.dumps(payload), 
                                    content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        self.assertEqual(data['prediction'], 0, "Failed to classify legitimate text correctly.")
        self.assertTrue(data['confidence'] > 0.5, "Confidence score is too low.")

if __name__ == '__main__':
    unittest.main()
