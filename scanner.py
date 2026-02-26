# ==============================================================================
# 🛡️ ThreatHunter AI
# © 2026 Harsh (@harsh160311). All rights reserved.
# 
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.
# ==============================================================================
import os
import platform
import subprocess
import time
import hashlib
import json
from PyQt5.QtCore import QThread, pyqtSignal

# Import Custom Logic Modules
# Ensure feature_extractor.py and model.py are in the same directory
from feature_extractor import extract_features
from model import predict

class ScanThread(QThread):
    # Define signals to communicate with the GUI (Progress bar, Logs, etc.)
    progress = pyqtSignal(str)
    threats = pyqtSignal(list)
    finished_signal = pyqtSignal()

    def __init__(self, folder):
        super().__init__()
        self.folder = folder
        self.is_running = True
        self.is_paused = False
        self.virus_db = {} 

    # --- CONTROL FUNCTIONS ---
    def stop(self):
        """Stops the scanning process safely."""
        self.is_running = False

    def toggle_pause(self):
        """Toggles the pause/resume state of the scanner."""
        self.is_paused = not self.is_paused

    # --- DATABASE LOADING (ABSOLUTE PATH FIX) ---
    def load_virus_db(self):
        """
        Loads the external JSON signature database securely.
        Uses absolute paths to ensure the file is found regardless of execution directory.
        """
        try:
            # Step 1: Find the directory where scanner.py is located
            base_dir = os.path.dirname(os.path.abspath(__file__))
            
            # Step 2: Build the full path to the malware_db.json file
            db_path = os.path.join(base_dir, "malware_db.json")
            
            if os.path.exists(db_path):
                with open(db_path, "r") as f:
                    self.virus_db = json.load(f)
                return True
            else:
                return False
        except Exception:
            return False

    # --- HASH CALCULATION UTILITY ---
    def calculate_sha256(self, file_path):
        """
        Calculates the SHA256 hash fingerprint of a file.
        Reads in 4KB chunks to optimize memory usage for large files.
        """
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except:
            return None

    # --- SYSTEM SECURITY CHECK ---
    def is_defender_active(self):
        """
        Checks if Windows Defender Real-Time Protection is currently enabled.
        Returns True if Active, False otherwise.
        """
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            # PowerShell command to query Defender status
            cmd = ["powershell", "-Command", "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, startupinfo=si)
            output, _ = proc.communicate()
            
            if "True" in output:
                return True
            return False
        except:
            return False

    # =========================================================
    # 🚀 MAIN LOGIC ENGINE
    # =========================================================
    def run(self):
        os_type = platform.system()
        threats = []
        
        # 1. Load Virus Signatures
        if self.load_virus_db():
             self.progress.emit(f"✔ Virus Database Loaded: {len(self.virus_db)} signatures ready.")
        else:
             self.progress.emit("⚠ Database not found. Running AI Scan only.")
        
        # 2. Define System Folders to Ignore (Optimization)
        ignore_folders = [
            'node_modules', '.git', '.vscode', '.idea', 'Android', 'Lib', 'site-packages', 
            '__pycache__', 'env', 'venv', 'AppData', '$RECYCLE.BIN', 'System Volume Information', 'Windows'
        ]
        
        # Files to exclude from scanning (Self-Protection)
        ignore_files = ['app.py', 'scanner.py', 'feature_extractor.py', 'model.py', 
                        'train_model.py', 'malware_model.pkl', 'malware_db.json', 'threats_log.txt']
        
        # 3. DEFINE WHITELISTS (False Positive Prevention)
        # Trust Paths: If a file is inside these folders, assume it is safe.
        # UPDATED FOR KALI LINUX & DEV TOOLS
        trusted_paths = [
            'tor browser', 'firefox', 'chrome', 'edge', 'google', 
            'steam', 'discord', 'spotify', 'adobe', 'program files', 'windows',
            
            # --- Kali Linux / Developer Specific Whitelist ---
            '.burpsuite',       # Burp Suite Security Tool
            '.npm',             # Node Package Manager Cache
            '.cache',           # System Cache (pip, thumbnails etc.)
            '.local/share/pipx',# Python Virtual Environments
            'node_modules',     # Developer Libraries
            'zphisher',         # Hacking Tool (False Positive Prevention)
            '.tunneler',        # Tunneling Tools
            'venvs'             # Virtual Environments
        ]
        
        # Trust Filenames: If the filename contains these words, assume it is safe.
        trusted_files = [
            '7z', 'recoverit', 'update', 'installer', 'setup', 'uninstall', 'upgrade',
            'python', 'activate.ps1', 'activate' # Python System Files
        ]

        self.progress.emit(">>> Initializing Hybrid Security Check...")

        # ============================================================
        # 🟢 PHASE 1: EXTERNAL SECURITY CHECK (Defender/ClamAV)
        # ============================================================
        
        if os_type == "Windows":
            self.progress.emit("\n>>> Phase 1: Checking Windows Defender Status...")
            defender_on = self.is_defender_active()
            
            if defender_on:
                # CASE A: Defender is ON -> Read logs only
                self.progress.emit("✔ Windows Defender is ACTIVE.")
                self.progress.emit(">>> Reading Defender Logs (Last 24h)...")
                
                try:
                    si = subprocess.STARTUPINFO()
                    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    log_cmd = ["powershell", "-Command", "Get-MpThreatDetection | Where-Object {$_.InitialDetectionTime -gt (Get-Date).AddDays(-1)} | Select ThreatName,Resources"]
                    proc_log = subprocess.Popen(log_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, startupinfo=si)
                    
                    found_log = False
                    for line in proc_log.stdout:
                        if line.strip() and "ThreatName" not in line and "---" not in line:
                            parts = line.split()
                            if len(parts) > 0:
                                t_name = parts[0]
                                clean_path = line.replace(t_name, "").strip()
                                threats.append({"name": f"Defender: {t_name}", "path": clean_path})
                                self.progress.emit(f"🔥 DEFENDER REPORT: {t_name}")
                                found_log = True
                    
                    if not found_log:
                        self.progress.emit("✔ Defender logs are clean.")
                except Exception:
                    pass
            else:
                # CASE B: Defender is OFF -> Issue Warning
                self.progress.emit("⚠ WARNING: Windows Defender is OFF!")
                self.progress.emit(">>> Phase 1: Engaging Emergency Database Scan.")

        elif os_type == "Linux":
             # CASE C: Linux (ClamAV)
            self.progress.emit("\n>>> Phase 1: Running ClamAV Deep Scan...")
            try:
                # Check if ClamAV is installed
                check_cmd = subprocess.run(["which", "clamscan"], stdout=subprocess.PIPE)
                if check_cmd.returncode == 0:
                    # Run ClamAV scan on the selected folder
                    cmd = ["clamscan", "-r", "--no-summary", "--infected", self.folder]
                    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    
                    for line in process.stdout:
                        if not self.is_running: 
                            process.terminate()
                            break
                        if "FOUND" in line:
                            # Parse ClamAV Output: "/path/to/file: VirusName FOUND"
                            parts = line.split(':')
                            if len(parts) >= 2:
                                v_name = parts[1].replace("FOUND", "").strip()
                                f_path = parts[0].strip()
                                threats.append({"name": f"ClamAV: {v_name}", "path": f_path})
                                self.progress.emit(f"🔥 MALWARE FOUND: {v_name}")
                    
                    self.progress.emit("✔ ClamAV Scan Completed.")
                else:
                    self.progress.emit("⚠ ClamAV not installed. Skipping Phase 1.")
            except Exception as e:
                self.progress.emit(f"ClamAV Error: {e}")

        # ============================================================
        # 🔴 PHASE 2: INTERNAL DEEP SCAN (Hash + AI)
        # ============================================================
        
        self.progress.emit("\n>>> Phase 2: Starting Internal Deep Scan...")
        file_count = 0
        
        # Traverse the directory tree
        for root, dirs, files in os.walk(self.folder):
            if not self.is_running: break
            while self.is_paused: time.sleep(0.5)
            
            # Filter out ignored folders
            dirs[:] = [d for d in dirs if d not in ignore_folders]
            
            for file in files:
                if not self.is_running: break 
                while self.is_paused: time.sleep(0.5)
                
                if file in ignore_files: continue
                
                file_path = os.path.join(root, file)
                file_count += 1
                
                # Emit progress every 50 files to avoid UI flooding
                if file_count % 50 == 0:
                    self.progress.emit(f"Scanning... ({file_count} files processed)")

                # ----------------------------------------------------
                # STEP A: SIGNATURE CHECK (Exact Match)
                # ----------------------------------------------------
                # This ensures 100% detection of known viruses in the database.
                if self.virus_db:
                    f_hash = self.calculate_sha256(file_path)
                    if f_hash in self.virus_db:
                        virus_name = self.virus_db[f_hash]
                        self.progress.emit(f"🚨 SIGNATURE MATCH: {virus_name}")
                        threats.append({"name": f"Signature: {virus_name}", "path": file_path})
                        continue # Virus found in DB, skip AI check.

                # ----------------------------------------------------
                # STEP B: AI PREDICTION (Unknown Threats)
                # ----------------------------------------------------
                
                # --- WHITELIST CHECK (Smart Logic) ---
                full_path_lower = file_path.lower()
                filename_lower = file.lower()
                
                # Check 1: Is the file in a Trusted Folder? (e.g., Tor Browser, .npm, .burpsuite)
                if any(tp in full_path_lower for tp in trusted_paths):
                    continue

                # Check 2: Is the filename Trusted? (e.g., python, setup, installer)
                if any(tf in filename_lower for tf in trusted_files):
                    continue

                # If NOT whitelisted, proceed with AI analysis
                features = extract_features(file_path)
                if features is None: continue
                
                verdict = predict(features)
                
                if "Malware" in verdict:
                    self.progress.emit(f"⚠ AI DETECTED: {file}")
                    threats.append({"name": f"AI: {verdict}", "path": file_path})

        self.progress.emit(f"\n✅ Scan Completed. Files Checked: {file_count}")
        self.threats.emit(threats)

        self.finished_signal.emit()
