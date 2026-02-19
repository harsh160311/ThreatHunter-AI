# 🛡️ ThreatHunter AI - Hybrid Malware Detection System

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20(Kali)-green?style=for-the-badge&logo=linux)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)
![AI Powered](https://img.shields.io/badge/AI-Random%20Forest-purple?style=for-the-badge)

**ThreatHunter AI** is an advanced, open-source malware detection tool designed for **Cybersecurity Researchers** and **Ethical Hackers**. It utilizes a **Hybrid Detection Engine** combining **Signature-Based Scanning** (SHA256) and **Heuristic AI Analysis** (Machine Learning) to detect zero-day threats.

> **Why this tool?** Traditional antiviruses only look for known signatures. ThreatHunter AI uses Machine Learning to detect *unknown* and *obfuscated* malware based on file behavior (Entropy & Keywords).

---

## ✨ Key Features

- **🧠 Hybrid AI Engine:** Detects unknown threats using a Random Forest Classifier trained on file entropy and suspicious keywords.
- **📂 Signature Scanning:** Matches file hashes against a local database of 800+ known malware signatures (sourced from MalwareBazaar).
- **🛡️ Windows Integration:** Automatically checks **Windows Defender Logs** before scanning to save time.
- **🐧 Linux Integration:** Seamlessly integrates with **ClamAV** for deep system scanning on Kali Linux/Ubuntu.
- **⚡ Smart Whitelisting:** Intelligent path-based whitelisting for Tor Browser, Burp Suite, NPM, and Python environments to prevent False Positives.
- **🖥️ Modern GUI:** Built with **PyQt5** featuring a professional Dark Mode interface, real-time logs, and progress tracking.

---

## 🛠️ Tech Stack & Libraries

This project is built using **Python 3** and requires the following libraries:

| Library | Purpose |
| :--- | :--- |
| **PyQt5** | For building the Graphical User Interface (GUI). |
| **scikit-learn** | For the Random Forest Machine Learning model. |
| **joblib** | For saving/loading the trained AI model (`.pkl`). |
| **requests** | For fetching malware database updates from the cloud. |
| **numpy** | For numerical operations in AI processing. |

---

## ⚙️ Installation Guide

### Prerequisites
- **Python 3.8+** installed.
- **Git** installed.
- **(Linux Only)** ClamAV installed: `sudo apt install clamav`

### 1️⃣ Clone the Repository
Open your terminal or command prompt and run:
```bash
# 1. Clone the repository
git clone [https://github.com/harsh160311/ThreatHunter-AI.git](https://github.com/harsh160311/ThreatHunter-AI.git)
cd ThreatHunter-AI

# 2. Update System & Install ClamAV
sudo apt update
sudo apt install clamav -y

# 3. Install Python Dependencies
sudo apt install python3-pyqt5 python3-sklearn python3-joblib python3-requests python3-numpy -y

# 4. Verify Files
ls

# 5. Update Database & Run App
python3 db_updater.py
python3 app.py


`````

Install Dependencies
For Windows:

Bash
pip install -r requirements.txt
For Kali Linux / Ubuntu:

Bash
sudo apt update
sudo apt install python3-pyqt5 python3-sklearn python3-joblib python3-requests
🚀 How to Run
🪟 On Windows (Automated)
We have included a smart batch script that updates the database, retrains the AI, and launches the app in one go.

Locate RunProject.bat in the folder.

Double-click it.

Wait for the initialization to complete.

(Or run manually via terminal):

Bash
python app.py
🐧 On Linux (Kali/Ubuntu)
Open your terminal in the project folder and run:

Bash
python3 app.py
🧠 How It Works (The Logic)
The scanner follows a strict Multi-Layered Security Protocol:

Phase 1: System Integrity Check

Windows: Checks if Windows Defender is active. If yes, it pulls recent threat logs.

Linux: Executes a clamscan on the target directory to find known Linux threats (like Rootkits/Webshells).

Phase 2: Deep Hybrid Scan

Layer A (Signature): Calculates SHA256 Hash of every file and checks it against malware_db.json.

Layer B (Whitelist): Checks if the file belongs to trusted applications (Tor, Firefox, Python venv) to avoid False Positives.

Layer C (AI Heuristics): If the file is unknown, the AI Engine analyzes its Entropy (Randomness) and Suspicious Keywords (e.g., eval, socket, powershell).

📂 Project Structure
ThreatHunter-AI/
├── app.py                 # Main GUI Application (Entry Point)
├── scanner.py             # Core Scanning Engine (Logic)
├── feature_extractor.py   # File Analysis Tool (Entropy & Keywords)
├── model.py               # AI Prediction Logic (The Brain)
├── train_model.py         # Script to Train/Retrain the AI Model
├── db_updater.py          # Script to Update Virus Database
├── malware_db.json        # Local Database of Virus Hashes
├── malware_model.pkl      # Trained AI Model File
├── RunProject.bat         # One-Click Launcher for Windows
├── requirements.txt       # List of Dependencies
└── README.md              # Documentation
⚠️ Disclaimer
For Educational Purposes Only.
This tool is designed to help cybersecurity enthusiasts and researchers understand malware analysis and antivirus architecture. The developer is not responsible for any damage caused by the misuse of this tool.
Always test malware in an isolated Virtual Machine (VM).

👨‍💻 Author
Harsh

Cybersecurity Enthusiast & Developer

