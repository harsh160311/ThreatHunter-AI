# ==============================================================================
# 🛡️ ThreatHunter AI
# © 2026 Harsh (@harsh160311). All rights reserved.
# 
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.
# ==============================================================================
import os
import joblib

model = None

def load_model():
    """Loads the pre-trained Random Forest model from disk."""
    global model
    try:
        if os.path.exists("malware_model.pkl"):
            model = joblib.load("malware_model.pkl")
    except Exception:
        pass

def predict(features):
    """
    Determines if a file is Safe or Malware based on extracted features.
    
    This function implements a Hybrid Logic:
    1. Heuristic Rules (Fast check for common false positives).
    2. AI Prediction (Random Forest Model).
    """
    global model
    if model is None:
        load_model()

    entropy = features[0]
    file_size = features[1]
    ext = features[2]
    keyword_hits = features[3]

    # ========================================================
    # 🛡️ RULE 1: SAFE INSTALLERS & LARGE APPLICATIONS
    # ========================================================
    # Real malware is usually small (KB to a few MB). 
    # Large files (>15MB) like Browsers/Games are highly unlikely to be simple viruses.
    if file_size > 15 * 1024 * 1024:
        return "Safe (Large Application/Installer)"

    # ========================================================
    # 🛡️ RULE 2: TEXT & LOG FILE PROTECTION
    # ========================================================
    # Prevents flagging ChangeLogs or Readme files unless they contain massive obfuscated code.
    if ext in ['.txt', '.log', '.md', '.rtf', '.xml', '.json', '.ini']:
        if keyword_hits > 30: 
            return f"Malware: Malicious Script ({keyword_hits} hits)"
        else:
            return "Safe (Text/Log File)"

    # ========================================================
    # 🛡️ RULE 3: WHITELISTED EXTENSIONS
    # ========================================================
    safe_extensions = [
        '.ttf', '.otf', '.woff', '.woff2', '.png', '.jpg', '.jpeg', '.gif', '.mp4',
        '.ja', '.xpi', '.lz4', '.pak', '.zip', '.rar', '.7z', '.gz', '.tar',
        '.css', '.html', '.svg', '.csv', '.sqlite', '.db', '.dat'
    ]
    if ext in safe_extensions:
        return "Safe (Media/Archive)"

    # ========================================================
    # 🧠 AI PREDICTION (FALLBACK)
    # ========================================================
    # Only consult AI if no Heuristic Rule matched.
    if model is not None:
        try:
            # Convert extension to binary feature for the model
            is_suspicious_ext = 1 if ext in ['.exe', '.dll', '.bat', '.ps1', '.vbs'] else 0
            
            prediction = model.predict([[entropy, file_size, keyword_hits, is_suspicious_ext]])[0]
            
            if prediction == 1:
                # --- FALSE POSITIVE CHECK ---
                # If AI says Malware, but the file looks like a clean packer (High Entropy, 0 Keywords)
                # We classify it as a Safe Installer (like 7-Zip setup).
                if keyword_hits == 0 and is_suspicious_ext == 1 and file_size > 1 * 1024 * 1024:
                    return "Safe (Packed Installer)"
                
                return f"Malware Detected (AI Confidence)"
            else:
                return "Safe (AI Verified)"
        except:
            return "Safe (Model Error)"


    return "Safe (Default)"
