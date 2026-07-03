import math
import hashlib
import secrets
import string
from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

def calculate_shannon_entropy(password):
    """
    Calculates the Shannon Entropy of the password string to check for character repetition/randomness.
    Formula: H(X) = -sum(p_i * log2(p_i))
    Returns entropy value per character.
    """
    if not password:
        return 0.0
    
    # Calculate frequency of each character
    frequencies = {}
    for char in password:
        frequencies[char] = frequencies.get(char, 0) + 1
        
    # Calculate Shannon Entropy
    entropy = 0.0
    length = len(password)
    for count in frequencies.values():
        p_i = count / length
        entropy -= p_i * math.log2(p_i)
        
    return round(entropy, 2)

def check_hibp_breach(password):
    """
    Secures password check against Have I Been Pwned API using k-Anonymity.
    Only sends the first 5 characters of the SHA-1 hash to the API.
    Returns (is_breached, breach_count).
    """
    try:
        # Calculate SHA-1 hash of the password
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Call the API sending only the prefix
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=3.0)
        
        if response.status_code == 200:
            # Parse responses: lines are in format 'SUFFIX:COUNT'
            hashes = (line.split(':') for line in response.text.splitlines())
            for h_suffix, count in hashes:
                if h_suffix == suffix:
                    return True, int(count)
            return False, 0
        else:
            # If HIBP API returns error codes, fail gracefully
            return None, 0
    except requests.RequestException:
        # Catch connection/timeout errors gracefully to support offline mode
        return None, 0

def format_time_to_crack(seconds):
    """
    Converts crack time in seconds to a human-readable string.
    """
    if seconds < 1:
        return "Instantly"
    
    # Time unit thresholds
    minutes = seconds / 60
    if minutes < 1:
        return f"{round(seconds, 1)} seconds"
        
    hours = minutes / 60
    if hours < 1:
        return f"{round(minutes)} minutes"
        
    days = hours / 24
    if days < 1:
        return f"{round(hours)} hours"
        
    months = days / 30
    if months < 1:
        return f"{round(days)} days"
        
    years = days / 365
    if years < 1:
        return f"{round(months)} months"
        
    centuries = years / 100
    if centuries < 1:
        return f"{round(years)} years"
        
    if centuries < 10000:
        return f"{round(centuries)} centuries"
        
    return "Eternity (Trillions of years)"

@app.route('/')
def home():
    """Renders the main dashboard of the Password Strength Analyzer."""
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_password():
    """
    API endpoint to analyze the password strength.
    Receives JSON body with 'password' field.
    Returns detailed JSON response with password score, feedback, entropy, breach check, etc.
    """
    data = request.get_json() or {}
    password = data.get('password', '')
    
    if not password:
        return jsonify({
            'score': 0,
            'strength': 'Empty',
            'length': 0,
            'criteria': {
                'length': False,
                'uppercase': False,
                'lowercase': False,
                'numbers': False,
                'symbols': False
            },
            'entropy_bits': 0,
            'shannon_entropy': 0.0,
            'time_to_crack': 'Instantly',
            'suggestions': ["Please enter a password to analyze."],
            'breached': False,
            'breach_count': 0,
            'breach_status': 'unknown'
        }), 200

    length = len(password)
    
    # 1. Criteria evaluation
    has_uppercase = any(char.isupper() for char in password)
    has_lowercase = any(char.islower() for char in password)
    has_digits = any(char.isdigit() for char in password)
    has_symbols = any(char in string.punctuation for char in password)
    is_length_ok = length >= 8
    
    # Count passed criteria
    criteria_score = sum([
        1 if is_length_ok else 0,
        1 if has_uppercase else 0,
        1 if has_lowercase else 0,
        1 if has_digits else 0,
        1 if has_symbols else 0
    ])

    # 2. Entropy calculations
    # Determine the character pool size based on character types present
    pool_size = 0
    if has_lowercase: pool_size += 26
    if has_uppercase: pool_size += 26
    if has_digits: pool_size += 10
    if has_symbols: pool_size += len(string.punctuation)  # typically 32 or 33
    
    # Edge case: If character pool size is 0 (unrecognized characters)
    if pool_size == 0:
        pool_size = 256 # Fallback to standard byte pool
        
    # Calculate Pool-Based Entropy: E = N * log2(R)
    pool_entropy = round(length * math.log2(pool_size), 1)
    
    # Calculate Shannon Entropy
    shannon_entropy = calculate_shannon_entropy(password)
    # Total Shannon Entropy estimation
    total_shannon_entropy = round(length * shannon_entropy, 1)

    # 3. Estimating Time to Crack
    # Assuming a high-speed guessing rate of 10 billion (1e10) hashes/second (GPU brute-force rig)
    guessing_rate = 1e10
    total_combinations = 2 ** pool_entropy
    seconds_to_crack = total_combinations / guessing_rate
    
    # Adjust time if Shannon Entropy is extremely low relative to length (e.g. repeated characters 'aaaaaa')
    # Because repeating pattern dictionary attacks or simple pattern reduction will crack it instantly
    if shannon_entropy < 1.5 and length > 4:
        seconds_to_crack = min(seconds_to_crack, 0.1) # Crack in < 0.1 seconds due to lack of character variety
        
    time_to_crack_str = format_time_to_crack(seconds_to_crack)

    # 4. Check for public data breaches
    is_breached, breach_count = check_hibp_breach(password)
    
    if is_breached is True:
        breach_status = 'breached'
    elif is_breached is False:
        breach_status = 'safe'
    else:
        breach_status = 'offline' # API was unreachable/timeout

    # 5. Generate Suggestions
    suggestions = []
    
    if not is_length_ok:
        suggestions.append(f"Make it longer. Current length is {length} characters. Passwords should be at least 8 characters (ideally 12-16+).")
    elif length < 12:
        suggestions.append("Improve length. While 8 characters is the minimum, 12+ characters significantly increases cracking time.")
        
    if not has_lowercase:
        suggestions.append("Add lowercase letters (a-z) to expand your password's character diversity.")
        
    if not has_uppercase:
        suggestions.append("Add uppercase letters (A-Z) to make it harder to guess.")
        
    if not has_digits:
        suggestions.append("Include at least one number (0-9).")
        
    if not has_symbols:
        suggestions.append("Incorporate special characters (e.g. !, @, #, $, %, etc.).")

    if shannon_entropy < 2.0 and length >= 6:
        suggestions.append("Avoid repeating characters or predictable patterns (e.g., 'aaaaaa' or '123123').")

    if breach_status == 'breached':
        suggestions.append(f"⚠️ WARNING: This password was found in a public data breach {breach_count:,} times! It is highly vulnerable. Change it immediately.")

    # 6. Overall Strength classification
    # If the password is breached, it is automatically marked as Weak
    if breach_status == 'breached':
        strength = 'Weak'
        final_score = min(criteria_score, 1) # Cap score to 1 if breached
    else:
        # Determine strength based on entropy and criteria
        if criteria_score >= 5 and pool_entropy >= 60 and shannon_entropy >= 2.5:
            strength = 'Strong'
            final_score = 5
        elif criteria_score >= 3 and pool_entropy >= 35:
            strength = 'Medium'
            final_score = 3
        else:
            strength = 'Weak'
            final_score = 1

    return jsonify({
        'score': final_score,
        'strength': strength,
        'length': length,
        'criteria': {
            'length': is_length_ok,
            'uppercase': has_uppercase,
            'lowercase': has_lowercase,
            'numbers': has_digits,
            'symbols': has_symbols
        },
        'entropy_bits': pool_entropy,
        'shannon_entropy': shannon_entropy,
        'time_to_crack': time_to_crack_str,
        'suggestions': suggestions,
        'breached': is_breached if is_breached is not None else False,
        'breach_count': breach_count,
        'breach_status': breach_status
    }), 200

@app.route('/api/generate', methods=['GET'])
def generate_password():
    """
    API endpoint to securely generate a random password using secrets module.
    Expects GET params: length, uppercase, lowercase, numbers, symbols
    """
    try:
        length = int(request.args.get('length', 12))
        length = max(8, min(64, length)) # Restrict length between 8 and 64
    except ValueError:
        length = 12

    use_upper = request.args.get('uppercase', 'true').lower() == 'true'
    use_lower = request.args.get('lowercase', 'true').lower() == 'true'
    use_digits = request.args.get('numbers', 'true').lower() == 'true'
    use_symbols = request.args.get('symbols', 'true').lower() == 'true'

    # Assemble password character sets
    char_sets = []
    required_chars = []
    
    if use_lower:
        char_sets.append(string.ascii_lowercase)
        required_chars.append(secrets.choice(string.ascii_lowercase))
    if use_upper:
        char_sets.append(string.ascii_uppercase)
        required_chars.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        char_sets.append(string.digits)
        required_chars.append(secrets.choice(string.digits))
    if use_symbols:
        char_sets.append(string.punctuation)
        required_chars.append(secrets.choice(string.punctuation))

    # If no options are selected, default to lowercase + uppercase + digits
    if not char_sets:
        char_sets = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
        required_chars = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits)
        ]

    # Combine all character pools
    full_pool = "".join(char_sets)
    
    # Calculate how many extra characters we need
    num_needed = length - len(required_chars)
    
    # If the requested length is less than the number of selected character sets
    if num_needed < 0:
        # truncate standard chars to fit requested length
        password_chars = required_chars[:length]
    else:
        # Securely pick extra characters from the complete pool
        extra_chars = [secrets.choice(full_pool) for _ in range(num_needed)]
        password_chars = required_chars + extra_chars
    
    # Securely shuffle the password list
    secrets.SystemRandom().shuffle(password_chars)
    generated_password = "".join(password_chars)
    
    return jsonify({
        'password': generated_password
    }), 200

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
