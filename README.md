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
   python file_integrity_checker.py
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
### **Example_Applications Folder:**
![Example Applications Folder](screenshots/example_applications.png)

### **CMD Output:**
![CMD Output](screenshots/cmd_output.png)

## 🤝 Contributing
Feel free to fork this repository and submit pull requests to improve the script!


