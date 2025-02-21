# 🛡️ File Integrity Checker with VirusTotal

## 🔍 Overview
This Python script scans files in the `Suspicious_Applications` folder, computes their SHA-256 hashes, and checks them against VirusTotal’s database to determine if they are **CLEAN, MALICIOUS, or UNKNOWN**.

## ⚙️ How It Works
- Scans files in `Suspicious_Applications/`
- Resolves `.lnk` shortcuts to actual `.exe` files
- Computes SHA-256 hash of each executable
- Checks the hash against VirusTotal
- Stores hashes in `trusted_hashes.json`
- Displays results in the command prompt

## 📂 Project Structure
```plaintext
📂 File-Integrity-Checker
│-- 📂 Suspicious_Applications/      # Folder where suspicious apps are placed
│-- 📜 file_integrity_checker.py  # Main script
│-- 📜 trusted_hashes.json        # Stores known file hashes
│-- 📜 README.md                  # Project documentation
│-- 📜 requirements.txt           # List of dependencies
│-- 📂 screenshots/               # CMD output and Example Applications folder
```

## 🚀 Installation & Setup
1. **Clone the Repository:**
   ```sh
   git clone https://github.com/bnmou/File-Integrity-Checker.git
   cd File-Integrity-Checker
   ```
2. **Install Dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
3. **Get a VirusTotal API Key:**
   - Sign up at [VirusTotal](https://www.virustotal.com/)
   - Get your API key from your profile settings
   - Replace `YOUR_VIRUSTOTAL_API_KEY` in `file_integrity_checker.py`

4. **Run the Script:**
   ```sh
   python "C:\Users\Owner\Desktop\File Integrity Checker\venv\File Integrity Checker.py"
   ```

## 🖥️ Example Usage
### 🔸 Dropping Suspicious Applications
Place any suspicious files into the `Suspicious_Applications` folder before running the script.

**Example Folder:**
```plaintext
📂 Suspicious_Applications/
│-- 📜 suspicious_app.exe
│-- 📜 unknown_installer.exe
```

### 🔹 Running the Script
```sh
python file_integrity_checker.py
```
**Example Output:**
```plaintext
Scanning files and verifying with VirusTotal...
File: C:\Users\Owner\Desktop\Example Applications\suspicious_app.exe | Hash: 4d3...c9a | VT Status: MALICIOUS
File: C:\Users\Owner\Desktop\Example Applications\unknown_installer.exe | Hash: 9e2...fba | VT Status: UNKNOWN
Trusted hash database updated.
```

## 📸 Screenshots
### **Suspicious_Applications Folder:**
![image](https://github.com/user-attachments/assets/6b06c603-d160-44fb-ab82-87442d2e56b8)

### **CMD Output:**
![image](https://github.com/user-attachments/assets/14aadf44-f77c-43ae-aa21-fc2690bae278)

## 📜 Source Code

```python
# Import required libraries
import hashlib
import os
import json
import requests
import win32com.client  # To resolve .lnk shortcut files

# Directory to scan (User's Example Applications)
DIRECTORIES = ["C:\\Users\\Owner\\Desktop\\File Integrity Checker\\Suspicious_Applications"]

# Trusted hash database file location
HASH_DATABASE = "C:\\Users\\Owner\\Desktop\\File Integrity Checker\\trusted_hashes.json"

# VirusTotal API Key (Replace with your API key)
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
VT_URL = "https://www.virustotal.com/api/v3/files/"

def compute_sha256(file_path):
    """Compute SHA-256 hash of a file."""
    try:
        with open(file_path, "rb") as f:
            sha256_hash = hashlib.sha256()
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error computing hash for {file_path}: {e}")
        return None

def resolve_lnk_target(lnk_path):
    """Resolve .lnk file to find the real target executable."""
    try:
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortcut(lnk_path)
        return shortcut.TargetPath  # Returns the actual executable path
    except Exception as e:
        print(f"Error resolving shortcut {lnk_path}: {e}")
        return None

def check_virustotal(file_hash):
    """Check file hash against VirusTotal API."""
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(VT_URL + file_hash, headers=headers)
    if response.status_code == 200:
        data = response.json()
        if data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0:
            return "MALICIOUS"
        else:
            return "CLEAN"
    elif response.status_code == 404:
        return "UNKNOWN"
    else:
        print(f"Error checking VirusTotal: {response.status_code}, {response.text}")
        return "ERROR"

def load_trusted_hashes():
    """Load trusted hashes from JSON file."""
    if not os.path.exists(HASH_DATABASE):
        return {}
    with open(HASH_DATABASE, "r") as f:
        return json.load(f)

def scan_and_verify():
    """Scan directory, compute hashes, and check with VirusTotal."""
    trusted_hashes = load_trusted_hashes()
    results = {}
    for directory in DIRECTORIES:
        if os.path.exists(directory):
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)

                    # If file is a .lnk shortcut, resolve to .exe
                    if file.endswith(".lnk"):
                        real_path = resolve_lnk_target(file_path)
                        if real_path and os.path.exists(real_path):
                            file_path = real_path  # Use actual .exe path
                        else:
                            print(f"Skipping unresolved shortcut: {file_path}")
                            continue

                    file_hash = compute_sha256(file_path)
                    if file_hash:
                        vt_status = check_virustotal(file_hash)
                        print(f"File: {file_path} | Hash: {file_hash} | VT Status: {vt_status}")
                        results[file_path] = {"hash": file_hash, "virustotal_status": vt_status}
    return results

def save_trusted_hashes(results):
    """Ensure directory exists and save computed hashes as the new trusted hashes."""
    os.makedirs(os.path.dirname(HASH_DATABASE), exist_ok=True)  # Create directory if not exists
    with open(HASH_DATABASE, "w") as f:
        json.dump(results, f, indent=4)
    print("Trusted hash database updated.")

if __name__ == "__main__":
    print("Scanning files and verifying with VirusTotal...")
    results = scan_and_verify()
    save_trusted_hashes(results)
    for file, data in results.items():
        print(f"[RESULT] {file} | Hash: {data['hash']} | VirusTotal Status: {data['virustotal_status']}")
```

## 🤝 Contributing
Feel free to fork this repository and submit pull requests to improve the script!


