import os
import re
import string
import random
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# Ensure target directories exist
os.makedirs("dataset", exist_ok=True)
os.makedirs("model", exist_ok=True)

# 1. Download NLTK data with fallback support
import nltk

NLTK_RESOURCES = ['stopwords', 'punkt', 'wordnet', 'omw-1.4']
NLTK_DOWNLOAD_SUCCESS = True

for resource in NLTK_RESOURCES:
    try:
        if resource == 'punkt':
            nltk.data.find('tokenizers/punkt')
        elif resource == 'stopwords':
            nltk.data.find('corpora/stopwords')
        elif resource == 'wordnet':
            nltk.data.find('corpora/wordnet')
        elif resource == 'omw-1.4':
            nltk.data.find('corpora/omw-1.4')
    except LookupError:
        try:
            print(f"Downloading NLTK resource: {resource}...")
            nltk.download(resource, quiet=True)
        except Exception as e:
            print(f"NLTK download failed for {resource}: {e}. Fallback preprocessor will be used if needed.")
            NLTK_DOWNLOAD_SUCCESS = False

from nltk.corpus import stopwords as nltk_stopwords
from nltk.tokenize import word_tokenize as nltk_word_tokenize
from nltk.stem import WordNetLemmatizer as NltkWordNetLemmatizer

# 2. Text Preprocessing logic
def preprocess_text(text):
    if not isinstance(text, str):
        return ""
    
    # Standard normalization
    text = text.lower()
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Remove punctuation
    text = text.translate(str.maketrans('', '', string.punctuation))
    
    if NLTK_DOWNLOAD_SUCCESS:
        try:
            tokens = nltk_word_tokenize(text)
            stop_words = set(nltk_stopwords.words('english'))
            lemmatizer = NltkWordNetLemmatizer()
            cleaned_tokens = [
                lemmatizer.lemmatize(word) 
                for word in tokens 
                if word not in stop_words and word.isalnum()
            ]
            return " ".join(cleaned_tokens)
        except Exception as e:
            pass  # If NLTK fails dynamically, slide into fallback
            
    # Fallback Preprocessor (100% offline-safe, no external dependencies)
    tokens = text.split()
    basic_stop_words = {
        "i", "me", "my", "myself", "we", "our", "ours", "ourselves", "you", "your", "yours", 
        "yourself", "yourselves", "he", "him", "his", "himself", "she", "her", "hers", "herself", 
        "it", "its", "itself", "they", "them", "their", "theirs", "themselves", "what", "which", 
        "who", "whom", "this", "that", "these", "those", "am", "is", "are", "was", "were", "be", 
        "been", "being", "have", "has", "had", "having", "do", "does", "did", "doing", "a", "an", 
        "the", "and", "but", "if", "or", "because", "as", "until", "while", "of", "at", "by", "for", 
        "with", "about", "against", "between", "into", "through", "during", "before", "after", "above", 
        "below", "to", "from", "up", "down", "in", "out", "on", "off", "over", "under", "again", "further", 
        "then", "once", "here", "there", "when", "where", "why", "how", "all", "any", "both", "each", 
        "few", "more", "most", "other", "some", "such", "no", "nor", "not", "only", "own", "same", "so", 
        "than", "too", "very", "s", "t", "can", "will", "just", "don", "should", "now"
    }
    
    cleaned = [word for word in tokens if word not in basic_stop_words and word.isalnum()]
    # Basic Stemmer fallback logic (strips ing, ed, s suffixes)
    stemmed = []
    for w in cleaned:
        if w.endswith('ing') and len(w) > 4:
            w = w[:-3]
        elif w.endswith('ed') and len(w) > 3:
            w = w[:-2]
        elif w.endswith('s') and len(w) > 3 and not w.endswith('ss'):
            w = w[:-1]
        stemmed.append(w)
    return " ".join(stemmed)


# 3. Robust Dataset Generator (Generates 1000+ realistic samples if CSV doesn't exist)
def generate_dataset_csv(filepath):
    print("Generating synthetic phishing and safe email dataset...")
    
    # Component banks
    phishing_subjects = [
        "Urgent: Action Required - Account Suspended",
        "Your Netflix membership is on hold - Update payment details",
        "PayPal Security Alert: Unauthorized login attempt detected",
        "Official Notification: You have won $1,000,000 Cash Prize!",
        "Verify your Bank Account details within 24 hours",
        "Security Update: Verify your Microsoft password immediately",
        "Invoice Payment Overdue - Please pay $450.99 now",
        "Blocked Transaction Notice - Call support center",
        "Amazon.com Customer Service: Claim your $100 Reward Voucher",
        "Cryptocurrency Alert: Your Bitcoin wallet has been compromised",
        "DHL Delivery Status: Shipment on hold, update address info",
        "FedEx Notification: Package delivery failure - click to update",
        "Tax Refund Voucher Request Form from IRS",
        "Employee portal password reset - Urgent verification",
        "Critical System Update required for your company login",
        "Warning: Facebook account security breach detected",
        "Apple ID locked: Confirm identity to unlock your account",
        "Bank Statement: Review suspicious wire transfers from your account",
        "Get rich quick! Invest in this secret stock now",
        "Claim your free gift card from Target"
    ]
    
    phishing_bodies = [
        "Dear customer, we detected unusual activities on your account. To prevent permanent suspension, you must verify your identity immediately by clicking on this link: {url}. Please do it within 24 hours.",
        "Your subscription has failed to renew because your credit card on file was declined. To avoid service disruption, please update your billing details here: {url} immediately. Thank you.",
        "We noticed a login to your account from an unrecognized device in {city}, {country}. If this wasn't you, please secure your profile by clicking this link: {url} and updating your password.",
        "Congratulations! Your email address has been selected as the grand prize winner of {money} in our promotional sweepstakes. To claim your reward, click here {url} and fill in the form.",
        "This is an official notice from your banking institution. Your access has been locked due to multiple failed login attempts. Verify your ownership by completing the security questionnaire at {url}.",
        "Your business email password will expire in 3 hours. Please click {url} to keep your current password and avoid losing access to your files and messages.",
        "Please find attached invoice #{invoice_num} for your recent purchase. The total amount due is {money}. Please review the payment terms at {url} and transfer funds to avoid penalty charges.",
        "A wire transfer of {money} to {name} is currently pending authorization. If you did not authorize this, click here {url} to cancel the transaction and claim a full refund.",
        "Congratulations on being a valued customer! We are giving away {money} shopping vouchers to random users. Claim your coupon code now at {url} before the offer expires tonight.",
        "We detected a secure wallet transfer request for {bitcoin_val} BTC. If you did not make this request, verify your private keys and cancel it instantly at {url}.",
        "Your parcel with tracking ID DHL-{invoice_num} has arrived at our warehouse but is on hold due to incorrect address information. Please pay the redelivery fee of $1.99 and update details at {url}.",
        "Your package from Amazon could not be delivered today. Click {url} to schedule a new delivery time and print your shipping label to avoid returned shipment.",
        "The IRS has calculated your tax return and determined you are eligible to receive a refund of {money}. Submit your direct deposit details at {url} to receive your funds immediately.",
        "An update to the employee benefit portal is online. All staff members must login at the portal page {url} using corporate credentials to select their health insurance options.",
        "We detected critical security gaps in your remote work software. Update your security credentials now at the login page: {url} to keep remote access working.",
        "Someone has requested to change your password from {city}. If you did not request this, please secure your account by logging in here: {url} immediately.",
        "Your Apple account has been suspended for security reasons. Click {url} to confirm your Apple ID and credit card details to restore services.",
        "A pending transaction of {money} from your checking account was flagged for fraud. To verify this transaction or dispute it, go to our security portal: {url}.",
        "Start earning {money} per day working from home for only 2 hours. This is a limited time opportunity. Register your banking details today at {url} to receive your starter kit.",
        "You have a pending Target gift card worth {money}. Click the link to claim your reward voucher: {url}. Offer ends in 24 hours."
    ]
    
    phishing_senders = [
        "support@paypal-security-update.com", "billing@netflx-renew.com", "alert@paypal-access-verify.net",
        "rewards@lottery-sweepstakes-int.com", "security@bank-verify-access.com", "admin@microsoft-security-auth.com",
        "invoices@overdue-billing-dept.com", "fraud-prevention@onlinebank-security.com", "promo@target-reward-claims.com",
        "bitcoin@wallet-security-update.com", "shipping@dhl-delivery-update.com", "fedex@shipping-label-portal.com",
        "refunds@irs-tax-portal.gov.net", "hr-benefits@company-employee-portal.com", "security-admin@company-login-patch.com",
        "security@facebook-alert-center.com", "billing@apple-id-verify.com", "security@chase-fraud-alert.com",
        "hr@work-from-home-careers.com", "promotions@target-giftcard-deals.com"
    ]
    
    phishing_urls = [
        "http://bit.ly/secure-login-392fk", "https://verify-paypal-identity-secure.com/login",
        "http://192.168.1.104/secure/netflix/update", "https://chase-bank-verify-account.net/login.php",
        "http://microsoft-password-reset.com/auth/login", "http://overdue-invoice-pdf-download.com",
        "https://target-promo-voucher-claim.info", "http://blockchain-wallet-security-keys.xyz",
        "http://dhl-package-tracking-address.net", "http://employee-benefits-portal-login.com",
        "https://irs-tax-refund-portal-direct.com/deposit", "http://facebook-security-breach-alert.com",
        "http://apple-id-restore-suspended-account.com", "http://work-from-home-careers-register.net"
    ]
    
    safe_subjects = [
        "Project Update: Weekly Sync and Deliverables",
        "Meeting Minutes: Product design review session",
        "Your monthly receipt for Spotify Premium subscription",
        "Re: Question about codebase refactoring",
        "Hi, are we still on for lunch tomorrow?",
        "Newsletter: Top coding trends for 2026",
        "Weekly status report - Engineering Team",
        "Invoice #4829 from AWS cloud services",
        "Welcome to Github! Let's get started with your account",
        "Quarterly Performance Review scheduling",
        "HR Notice: Holidays calendar for 2026",
        "Draft proposal for client website redesign",
        "Thank you for your order! Receipt from Uber Eats",
        "Upcoming system maintenance window: Sunday 2 AM",
        "Bug ticket #9283 has been resolved by developer",
        "Family dinner plans - Sunday night details",
        "Conference registration confirmation: PyCon 2026",
        "GitHub Pull Request merged: Fix navbar alignment",
        "Notes from our mentoring session yesterday",
        "Feedback request: New onboarding documentation"
    ]
    
    safe_bodies = [
        "Hi Team, please find the weekly project updates and metrics slide deck attached. Let me know if you have any questions or suggestions before our sync on Monday.",
        "Here are the minutes from today's product design review. We decided to go ahead with the dark mode layout. Action items are assigned in Jira, let's target completing them by Wednesday.",
        "Thank you for your payment. Your Spotify Premium subscription has been renewed. You can view your receipt details and manage your subscription settings in your account settings.",
        "Hey! Yes, I looked at the codebase refactoring. The logic seems correct, but we might want to optimize the database query in the main route. Let's discuss it further.",
        "Hey, just checking if you are still free for lunch tomorrow at 1:00 PM? There is a new Italian restaurant nearby that we should try.",
        "In this week's issue, we cover the latest updates in Python 3.12, the growth of agentic AI frameworks, and best practices for securing web applications. Happy reading!",
        "Hi all, here is my weekly status report. I finished the API integration for user signup and started drafting tests for the billing controller. Next week, I'll focus on deployment.",
        "Your monthly AWS bill is ready. The total charge of {money} has been billed to your credit card ending in {invoice_num}. View the full cost breakdown in your Billing Console.",
        "Welcome to the community! We are excited to have you. Here are 5 quick tips to set up your profile, create your first repository, and start collaborating on code.",
        "Hi {name}, it's time for our quarterly performance review. Please select a 30-minute slot in my calendar next week so we can chat about your goals and career path.",
        "Dear employees, please note that the offices will be closed on the upcoming public holidays. Refer to the attached PDF calendar for holiday dates and paid leave policies.",
        "Hi client, please find the draft proposal for your website redesign. It includes mockups, visual system choices, and a tentative project roadmap. Let us know your thoughts.",
        "Thanks for ordering from Uber Eats! Your food is on its way. The total charge was {money}. You can track your courier's location in the app.",
        "Please be advised that we will be performing scheduled server maintenance this Sunday between 2:00 AM and 4:00 AM. Expect brief downtime on the internal portal.",
        "Hi, bug ticket #{invoice_num} regarding the checkout form crash on Safari has been resolved. The fix is deployed to the staging environment for verification.",
        "Hey, we are planning family dinner at Mom's place this Sunday at 6 PM. Let me know if you can bring some dessert or drinks. Looking forward to seeing everyone!",
        "Your registration for PyCon 2026 is confirmed. Your ticket ID is PY-{invoice_num}. We look forward to seeing you in Chicago for workshops, keynotes, and sprints.",
        "Great job! Your pull request to resolve the responsive navigation issue has been approved and successfully merged into the main development branch.",
        "Thanks for the chat yesterday during our mentoring session. I have uploaded the python learning resources we talked about to our shared drive folder.",
        "Hi everyone, we just updated the developer onboarding guide. Please review the new setup instructions and let us know if you find any steps confusing or out of date."
    ]
    
    safe_senders = [
        "pm@company.com", "designer@company.com", "no-reply@spotify.com",
        "techlead@company.com", "friend@gmail.com", "newsletter@pythonweekly.com",
        "developer@company.com", "billing@aws.amazon.com", "noreply@github.com",
        "manager@company.com", "hr@company.com", "agency@webdesign.com",
        "receipts@ubereats.com", "it-support@company.com", "jira@company.atlassian.net",
        "sister@yahoo.com", "registration@pycon.org", "notifications@github.com",
        "mentor@company.com", "documentation@company.com"
    ]
    
    safe_urls = [
        "https://github.com/company/project", "https://aws.amazon.com/console",
        "https://spotify.com/account", "https://jira.company.net/browse/T-92",
        "https://calendly.com/manager/review", "https://pycon.org/2026/tickets",
        "https://meet.google.com/abc-defg-hij", "https://drive.google.com/drive/folders/123"
    ]
    
    # Generate balanced records
    records = []
    
    # Helper to randomize variables in text
    def fill_variables(text, label):
        city = random.choice(["London", "New York", "Paris", "Berlin", "Sydney", "Tokyo", "Toronto"])
        country = random.choice(["UK", "USA", "France", "Germany", "Australia", "Japan", "Canada"])
        money = random.choice(["$45.50", "$150.00", "$499.99", "$1,250.00", "$5,000.00"])
        bitcoin_val = random.choice(["0.05", "0.12", "0.34", "1.15", "2.5"])
        invoice_num = str(random.randint(10000, 99999))
        name = random.choice(["John Doe", "Alice Smith", "Michael Johnson", "David Miller", "Sarah Connor"])
        
        # Pick URL based on category
        url_choice = random.choice(phishing_urls) if label == 1 else random.choice(safe_urls)
        # 10% chance of no URL for safe emails
        if label == 0 and random.random() < 0.2:
            url_choice = ""
            
        formatted = text.format(
            city=city, country=country, money=money, bitcoin_val=bitcoin_val,
            invoice_num=invoice_num, name=name, url=url_choice
        )
        return formatted, url_choice

    # Generate 550 Phishing and 550 Safe emails (Total 1100)
    # Phishing Loop
    for i in range(550):
        subj = random.choice(phishing_subjects)
        body_template = random.choice(phishing_bodies)
        body, url = fill_variables(body_template, label=1)
        sender = random.choice(phishing_senders)
        records.append({
            "subject": subj,
            "body": body,
            "sender": sender,
            "url": url,
            "label": 1
        })
        
    # Safe Loop
    for i in range(550):
        subj = random.choice(safe_subjects)
        body_template = random.choice(safe_bodies)
        body, url = fill_variables(body_template, label=0)
        sender = random.choice(safe_senders)
        records.append({
            "subject": subj,
            "body": body,
            "sender": sender,
            "url": url,
            "label": 0
        })
        
    df = pd.DataFrame(records)
    # Shuffle dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(filepath, index=False)
    print(f"Dataset generated and saved successfully to {filepath} ({len(df)} rows).")

# 4. Main Training Loop
def main():
    csv_path = os.path.join("dataset", "phishing_emails.csv")
    if not os.path.exists(csv_path):
        generate_dataset_csv(csv_path)
    
    # Load dataset
    print("Loading dataset...")
    df = pd.read_csv(csv_path)
    
    # Fill empty values
    df['subject'] = df['subject'].fillna("")
    df['body'] = df['body'].fillna("")
    df['sender'] = df['sender'].fillna("")
    df['url'] = df['url'].fillna("")
    
    # Combine fields to construct rich context features for NLP
    print("Combining text features...")
    df['combined_text'] = df['sender'] + " " + df['subject'] + " " + df['body'] + " " + df['url']
    
    # Preprocess text
    print("Preprocessing text data...")
    df['processed_text'] = df['combined_text'].apply(preprocess_text)
    
    # Split training and testing sets
    X = df['processed_text']
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Vectorization
    print("Fitting TF-IDF Vectorizer...")
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    X_train_vectorized = vectorizer.fit_transform(X_train)
    X_test_vectorized = vectorizer.transform(X_test)
    
    # Model Training
    print("Training Multinomial Naive Bayes model...")
    model = MultinomialNB(alpha=0.1)
    model.fit(X_train_vectorized, y_train)
    
    # Evaluation
    predictions = model.predict(X_test_vectorized)
    accuracy = accuracy_score(y_test, predictions)
    print(f"\n--- Model Evaluation Results ---")
    print(f"Accuracy Score: {accuracy:.4f} ({accuracy*100:.2f}%)")
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=["Safe", "Phishing"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))
    print(f"--------------------------------")
    
    # Save the models
    model_path = os.path.join("model", "phishing_model.pkl")
    vectorizer_path = os.path.join("model", "vectorizer.pkl")
    
    print(f"Saving model to {model_path}...")
    joblib.dump(model, model_path)
    
    print(f"Saving vectorizer to {vectorizer_path}...")
    joblib.dump(vectorizer, vectorizer_path)
    print("Training pipeline completed successfully.")

if __name__ == "__main__":
    main()
