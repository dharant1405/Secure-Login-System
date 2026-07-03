# Phishing Email Detection Web Application

A machine learning-powered web application that detects phishing and social engineering indicators in email text payloads. The system uses **TF-IDF Vectorization** for text extraction and a **Multinomial Naive Bayes** classifier to predict email legitimacy, wrapped in a high-fidelity, cyber security-themed Bootstrap dashboard.

---

## 🔬 Classifier Specifications

### 1. Feature Extraction (TF-IDF)
* **TF-IDF (Term Frequency-Inverse Document Frequency)** is applied to convert email text into numerical feature matrices. 
* Case-normalization and English stop-word removal are enforced to prioritize vocabulary with high information entropy.

### 2. Machine Learning Model (Naive Bayes)
* **Algorithm**: `MultinomialNB` (Naive Bayes Classifier for multinomial models).
* **Rationale**: Naive Bayes assumes class-conditional independence between terms, which is extremely effective and computationally lightweight for text classification tasks like spam and phishing filtering.

### 3. Real-Time Indicator Highlighting
* The web backend processes the input string against a custom high-risk regex repository (e.g. `urgent`, `verify credentials`, `suspended`, `wire transfer`) and returns matching phrases.
* The frontend Javascript dynamically wraps these tokens in `<span class="flagged-indicator">` tags to highlight social engineering clues.

---

## 📊 Training & Evaluation Report

The model was trained on a balanced corpus of 150 emails (75 phishing / 75 legitimate).

### Performance Metrics (Scikit-Learn Output):
* **Accuracy**: **96.67%** (Classifier successfully predicts 29 out of 30 test partition samples)
* **Precision**: **93.75%** (High probability that emails classified as phishing are actual threats)
* **Recall (Sensitivity)**: **100.00%** (Zero false negatives; the classifier captured 100% of actual phishing threats in the test set)
* **F1-Score**: **96.77%** (Harmonic mean of precision and recall)

### Confusion Matrix Matrix:
```
               Predicted Safe    Predicted Phishing
Actual Safe          14 (TN)           1 (FP)
Actual Phish          0 (FN)          15 (TP)
```
* **True Negatives (TN)**: 14 safe emails correctly identified.
* **False Positives (FP)**: 1 safe email falsely flagged as phishing.
* **False Negatives (FN)**: 0 phishing emails missed (Critical success parameter).
* **True Positives (TP)**: 15 phishing emails correctly identified.

---

## 🛠️ Step-by-Step Installation & Run Guide

### 1. Install Dependencies
Run pip to install python packages:
```bash
pip install -r requirements.txt
```

### 2. Execute Training Script (If rebuilding model)
To recompile the corpus, train the model, and serialize metrics:
```bash
python train_model.py
```
This updates `models/phishing_model.pkl`, `models/tfidf_vectorizer.pkl`, and `models/evaluation_metrics.json`.

### 3. Launch Flask Server
Start the local server loop:
```bash
python app.py
```
*Note: The server runs on port **5001** to avoid port collisions with the Secure Login System running on port 5000.*

### 4. Open in Web Browser
Go to:
```url
http://127.0.0.1:5001/
```
Paste suspicious text to scan for threat vectors.
