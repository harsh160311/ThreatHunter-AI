import sys
import os
import platform
import subprocess  # Added missing import
import db_updater  # Added missing import
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QTextEdit, QLabel, QFileDialog, QProgressBar)
from PyQt5.QtGui import QTextCursor, QColor, QTextCharFormat 
from PyQt5.QtCore import Qt
from scanner import ScanThread  # Ensure scanner.py is in the same folder

# Ensure results directory exists for logs
if not os.path.exists("results"):
    os.makedirs("results")

class MalwareScanner(QWidget):
    def __init__(self):
        super().__init__()
        # --- WINDOW CONFIGURATION ---
        self.setWindowTitle("ThreatHunter AI - Professional Edition")
        self.setGeometry(100, 100, 950, 700)
        self.folder_path = ""
        self.thread = None
        
        # --- THEME STYLING (Dark Mode) ---
        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #e0e0e0;
                font-family: 'Segoe UI', sans-serif;
            }
            QLabel#Title {
                font-size: 22px;
                font-weight: bold;
                color: #00e676; 
                padding: 10px;
            }
            QLabel#Status {
                font-size: 16px;
                font-weight: bold;
                color: #cfcfcf;
                border: 1px solid #333;
                border-radius: 5px;
                padding: 8px;
                background-color: #1e1e1e;
            }
            QPushButton {
                background-color: #2c2c2c;
                border: 2px solid #333;
                border-radius: 8px;
                color: white;
                font-size: 14px;
                padding: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #3d3d3d;
                border: 2px solid #00e676; 
            }
            QPushButton:pressed {
                background-color: #00e676;
                color: black;
            }
            QPushButton#StopBtn {
                border: 2px solid #ff4444;
            }
            QPushButton#StopBtn:hover {
                background-color: #550000;
            }
            QPushButton:disabled {
                background-color: #1a1a1a;
                color: #555;
                border: 2px solid #1a1a1a;
            }
            QTextEdit {
                background-color: #0d0d0d;
                border: 1px solid #333;
                border-radius: 5px;
                color: #00ff00; 
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 13px;
                padding: 10px;
            }
            QProgressBar {
                border: 2px solid #333;
                border-radius: 5px;
                text-align: center;
                background-color: #1a1a1a;
                color: white;
            }
            QProgressBar::chunk {
                background-color: #00e676;
                width: 10px;
                margin: 0.5px;
            }
        """)
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # 1. HEADER SECTION
        header_layout = QHBoxLayout()
        self.title_label = QLabel("🛡️ THREATHUNTER AI DETECTOR")
        self.title_label.setObjectName("Title")
        header_layout.addWidget(self.title_label)
        main_layout.addLayout(header_layout)

        # 2. STATUS BAR
        # Using platform library to detect OS immediately
        os_name = platform.system()
        os_version = platform.release()
        self.status_label = QLabel(f"System Status: IDLE | Host: {os_name} {os_version}")
        self.status_label.setObjectName("Status")
        self.status_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.status_label)

        # 3. CONTROL BUTTONS
        btn_layout = QHBoxLayout()
        
        self.folder_button = QPushButton("📂 SELECT FOLDER")
        self.folder_button.setCursor(Qt.PointingHandCursor)
        self.folder_button.clicked.connect(self.select_folder)
        
        self.scan_button = QPushButton("🚀 START SCAN")
        self.scan_button.setCursor(Qt.PointingHandCursor)
        self.scan_button.clicked.connect(self.start_scan)
        self.scan_button.setEnabled(False)

        self.pause_button = QPushButton("⏸ PAUSE")
        self.pause_button.clicked.connect(self.toggle_pause)
        self.pause_button.setEnabled(False)

        self.stop_button = QPushButton("⏹ STOP")
        self.stop_button.setObjectName("StopBtn")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)

        btn_layout.addWidget(self.folder_button)
        btn_layout.addWidget(self.scan_button)
        btn_layout.addWidget(self.pause_button)
        btn_layout.addWidget(self.stop_button)
        main_layout.addLayout(btn_layout)

        # 4. PROGRESS BAR
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.hide()
        main_layout.addWidget(self.progress_bar)

        # 5. CONSOLE LOG OUTPUT
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        main_layout.addWidget(self.text_edit)
        
        # --- INITIAL SYSTEM CHECK LOGS ---
        self.text_edit.append(f">>> Initializing Security Engine...")
        self.text_edit.append(f">>> Host OS Detected: {os_name} {os_version}")
        self.text_edit.append(f">>> Architecture: {platform.machine()}")
        self.text_edit.append(">>> Waiting for user command...\n")

        # Footer
        footer = QLabel("Powered by ThreatHunter AI Engine")
        footer.setStyleSheet("color: #555; font-size: 11px;")
        footer.setAlignment(Qt.AlignRight)
        main_layout.addWidget(footer)

        self.setLayout(main_layout)

    # --- BUTTON FUNCTIONS ---
    def select_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if folder:
            self.folder_path = folder
            self.status_label.setText(f"Target: {folder}")
            self.scan_button.setEnabled(True)
            self.text_edit.append(f">>> Target Directory Set: {folder}")

    def start_scan(self):
        if not self.folder_path:
            return
        
        # UI Updates during scan
        self.scan_button.setEnabled(False)
        self.folder_button.setEnabled(False)
        self.pause_button.setEnabled(True)
        self.stop_button.setEnabled(True)
        self.text_edit.clear()
        self.progress_bar.show()
        
        self.status_label.setText("Status: Scanning in progress...")
        self.status_label.setStyleSheet("color: #FFC107; border: 2px solid #FFC107; background-color: #332200; padding: 8px; font-weight: bold; font-size: 16px;")

        # Start Background Thread
        self.thread = ScanThread(self.folder_path)
        self.thread.progress.connect(self.update_progress)
        self.thread.threats.connect(self.show_threats)
        self.thread.finished_signal.connect(self.scan_finished)
        self.thread.start()

    def toggle_pause(self):
        if self.thread:
            self.thread.toggle_pause()
            if self.thread.is_paused:
                self.pause_button.setText("▶ RESUME")
                self.status_label.setText("Status: Paused")
            else:
                self.pause_button.setText("⏸ PAUSE")
                self.status_label.setText("Status: Scanning...")

    def stop_scan(self):
        if self.thread:
            self.thread.stop()
            self.status_label.setText("Status: Aborting...")
            self.text_edit.append(">>> Scan Aborted by User.")

    # --- LOGIC & REPORTING ---
    def update_progress(self, text):
        self.text_edit.append(text)
        cursor = self.text_edit.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.text_edit.setTextCursor(cursor)

    def scan_finished(self):
        self.scan_button.setEnabled(True)
        self.folder_button.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        self.progress_bar.hide()
        self.pause_button.setText("⏸ PAUSE")

    def show_threats(self, threats):
        """Displays the final threat report in the console and saves to file."""
        if threats:
            self.status_label.setText(f"⚠ THREATS DETECTED: {len(threats)}")
            self.status_label.setStyleSheet("color: #ff3333; border: 2px solid #ff3333; background-color: #330000; padding: 8px; font-weight: bold; font-size: 18px;")
            
            self.text_edit.append("\n" + "="*40)
            self.text_edit.append("🚨 FINAL SECURITY REPORT")
            self.text_edit.append("="*40)

            # Save report to file
            with open("results/threats_log.txt", "w") as f:
                f.write("THREATHUNTER AI - DETECTION LOG\n=================================\n")
                
                for i, threat in enumerate(threats, 1):
                    cursor = self.text_edit.textCursor()
                    cursor.movePosition(QTextCursor.End)
                    
                    fmt = QTextCharFormat() 
                    
                    # Highlight Virus Name in Red
                    fmt.setForeground(QColor('#ff3333')); fmt.setFontWeight(75); cursor.setCharFormat(fmt)
                    cursor.insertText(f"{i}. [MALWARE] {threat['name']}\n")
                    
                    # Highlight Path in Orange
                    fmt.setForeground(QColor('#ffaa00')); fmt.setFontWeight(50); cursor.setCharFormat(fmt)
                    cursor.insertText(f"    Target: {threat['path']}\n\n")
                    
                    f.write(f"{i}. {threat['name']} | Path: {threat['path']}\n")
            
            self.text_edit.setTextColor(QColor('#ffffff'))
            self.text_edit.append(">>> Detailed report saved to: results/threats_log.txt")
        else:
            self.status_label.setText("✅ SYSTEM SECURE")
            self.status_label.setStyleSheet("color: #00e676; border: 2px solid #00e676; background-color: #002200; padding: 8px; font-weight: bold; font-size: 18px;")
            self.text_edit.setTextColor(QColor('#00e676'))
            self.text_edit.append("\n✅ NO ANOMALIES DETECTED.")
            self.text_edit.append("System is clean.")
            self.text_edit.setTextColor(QColor('#00ff00'))

if __name__ == "__main__":
    print("------------------------------------------------")
    print("🚀 SYSTEM STARTUP SEQUENCE INITIATED")
    print("------------------------------------------------")

    # --- STEP 1: TRAIN THE AI MODEL ---
    print("🧠 [1/3] Training AI Model. Please wait...")
    try:
        # Automatically use 'python' for Windows and 'python3' for Linux
        py_command = "python" if platform.system() == "Windows" else "python3"
        subprocess.run([py_command, "train_model.py"], check=True)
        print("✅ AI Model Trained Successfully!")
    except Exception as e:
        print(f"⚠ Warning: AI Training Failed: {e}")

    # --- STEP 2: UPDATE THE DATABASE ---
    print("\n🔄 [2/3] Updating Malware Database...")
    try:
        db_updater.update_database()
    except Exception as e:
        print(f"⚠ Update Failed (Running in Offline Mode): {e}")

    # --- STEP 3: OPEN THE APP (GUI) ---
    print("\n💻 [3/3] Starting User Interface...")
    app = QApplication(sys.argv)
    window = MalwareScanner()
    window.show()
    sys.exit(app.exec_())
