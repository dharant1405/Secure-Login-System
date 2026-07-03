import requests
import json

BASE_URL = "http://127.0.0.1:5000"

def test_analyze():
    print("--- TESTING PASSWORD ANALYSIS API ---")
    
    # 1. Test weak password
    print("Testing weak password '123456'...")
    resp = requests.post(f"{BASE_URL}/api/analyze", json={"password": "123456"})
    if resp.status_code == 200:
        data = resp.json()
        print(f"Strength: {data['strength']}")
        print(f"Score: {data['score']}")
        print(f"Entropy: {data['entropy_bits']} bits")
        print(f"Breached: {data['breached']} (Count: {data['breach_count']})")
        # Use ascii encoding to avoid windows console print errors
        cleaned_suggestions = [s.encode('ascii', 'replace').decode('ascii') for s in data['suggestions']]
        print(f"Suggestions: {cleaned_suggestions}")
    else:
        print(f"Failed with status: {resp.status_code}")
        
    print("\n------------------------------------\n")
    
    # 2. Test strong password
    print("Testing strong password 'C0mpl3x!P@ssw0rd2026'...")
    resp = requests.post(f"{BASE_URL}/api/analyze", json={"password": "C0mpl3x!P@ssw0rd2026"})
    if resp.status_code == 200:
        data = resp.json()
        print(f"Strength: {data['strength']}")
        print(f"Score: {data['score']}")
        print(f"Entropy: {data['entropy_bits']} bits")
        print(f"Breached: {data['breached']}")
        cleaned_suggestions = [s.encode('ascii', 'replace').decode('ascii') for s in data['suggestions']]
        print(f"Suggestions: {cleaned_suggestions}")
    else:
        print(f"Failed with status: {resp.status_code}")

def test_generate():
    print("\n--- TESTING PASSWORD GENERATOR API ---")
    resp = requests.get(f"{BASE_URL}/api/generate?length=16&uppercase=true&lowercase=true&numbers=true&symbols=true")
    if resp.status_code == 200:
        data = resp.json()
        print(f"Generated Password: {data['password']}")
        print(f"Length: {len(data['password'])}")
    else:
        print(f"Failed with status: {resp.status_code}")

if __name__ == "__main__":
    try:
        test_analyze()
        test_generate()
    except Exception as e:
        print(f"Error testing APIs: {e}")
