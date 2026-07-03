# Phishing Email Detection Model - AegisGuard Dashboard

An intelligent, production-quality cyber threat intelligence system that detects and classifies phishing emails in real-time. It pairs a **Multinomial Naive Bayes classifier** with advanced **structural threat heuristics** to flag malicious vectors, gauge threat confidence, and present actionable mitigation protocols.

Designed as an industry-grade university internship or portfolio project with a high-fidelity cyberpunk dark theme.

## 🚀 Features

*   **Dual-Engine Hybrid Classifier:**
    *   **Machine Learning (NLP):** Tokenizes, filters stop words, lemmatizes text, fits `TfidfVectorizer` (ngram range 1-2), and classifies via `MultinomialNB`.
    *   **Cyber Threat Heuristics:** Scans sender domain typosquatting, insecurity markers (HTTP vs HTTPS), IP address hostings in URLs, subdomain densities, and textual urgency triggers.
*   **Modern Cyber Security Dashboard:**
    *   Responsive design using Bootstrap 5, Outfit typography, and custom neon styles.
    *   Glassmorphic panels, real-time threat index stats, and circular SVG metrics gauges.
    *   Interactive multi-stage scanning animation simulating a threat control center analysis.
*   **User Utilities:**
    *   **Drag & Drop File Upload:** Automatically parses `.txt` emails into subject, sender, link, and text fields.
    *   **Simulation Templates:** Quick buttons to pre-fill known threat vectors (lottery scam, billing fraud) or benign business letters.
    *   **Auditable Verification:** Generates random Aegis Transaction IDs, audit summaries, and a print-optimized stylesheet for reporting.

---

## 🛠️ Technologies Used

*   **Core Backend:** Python 3.13, Flask
*   **Machine Learning & NLP:** Scikit-learn, Pandas, NumPy, NLTK, Joblib
*   **Frontend UI:** HTML5 (Semantic), CSS3 (Vanilla), JavaScript (ES6+), Bootstrap 5, FontAwesome 6

---

## 📁 Folder Structure

```text
Phishing-Email-Detection/
│
├── app.py                  # Flask Application server & routing API
├── train_model.py          # Dataset generator & Model training pipeline
├── predict.py              # Threat classification wrapper & heuristic rules
├── test_app.py             # Automated unit tests for routing & pipeline validation
├── requirements.txt        # Project dependencies list
├── README.md               # Complete project documentation
│
├── dataset/
│   └── phishing_emails.csv # Generated balanced corpus (1,100 records)
│
├── model/
│   ├── phishing_model.pkl  # Trained Multinomial Naive Bayes classifier
│   └── vectorizer.pkl      # Saved TF-IDF Feature extractor
│
├── templates/
│   ├── index.html          # Dashboard inputs interface
│   └── result.html         # Threat Verdict Report & Recommendations
│
└── static/
    ├── css/
    │   └── style.css       # Premium cyber-themed stylesheet
    └── js/
        └── script.js       # Client validations, file parser, scan animations
```

---

## ⚙️ Installation & Setup

1.  **Clone or Open the Project Directory:**
    ```bash
    cd Phishing-Email-Detection
    ```

2.  **Install Required Libraries:**
    Ensure you have Python 3 installed. Install dependencies using:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Train the Classifier:**
    Run the training pipeline script. This automatically downloads NLTK assets (`stopwords`, `punkt`, `wordnet`), generates the balanced 1,100 row dataset, compiles features, trains the model, and outputs saved pickles:
    ```bash
    python train_model.py
    ```

4.  **Run the Automated Test Suite:**
    Confirm pipeline integrity and server endpoints by executing:
    ```bash
    python test_app.py
    ```

---

## 💻 How to Run the App

Launch the local development server:
```bash
python app.py
```

Open your browser and navigate to:
```text
http://127.0.0.1:5000/
```

### Usage Steps:
1.  Click on any of the **Threat Templates** on the right sidebar to pre-populate the form with sample threat/safe models, or write your own.
2.  Alternatively, drag and drop a raw email `.txt` file into the upload zone. It will parse and populate fields.
3.  Click **Scan & Run Threat Analysis**.
4.  Observe the AegisGuard scanning animation as it analyzes the inputs.
5.  Review the **Threat Verdict Report** showing class confidence, risk meters, flags triggered, and recommended safety actions.
6.  Click **Print Security Report** to export or save the report as PDF.
