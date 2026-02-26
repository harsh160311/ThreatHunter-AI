# ==============================================================================
# 🛡️ ThreatHunter AI
# © 2026 Harsh (@harsh160311). All rights reserved.
# 
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.
# ==============================================================================
import math
import os
from collections import Counter

def extract_features(file_path):
    """
    Analyzes a file to extract metadata and statistical features for AI processing.
    
    Args:
        file_path (str): Path to the file being analyzed.
        
    Returns:
        list: [Entropy, File_Size, Extension, Keyword_Hits] OR None if error.
    """
    try:
        # --- Step 1: File Size Validation ---
        # We skip extremely large files (>50MB) to prevent system lag during extraction.
        file_size = os.path.getsize(file_path)
        if file_size > 50 * 1024 * 1024: 
            return [0, 0, "", 0]

        # --- Step 2: Extension Extraction ---
        _, extension = os.path.splitext(file_path)
        extension = extension.lower()

        # Define a whitelist of safe media/system extensions to skip unnecessary processing.
        skip_exts = ['.mp4', '.mkv', '.avi', '.mp3', '.wav', '.iso', '.sys', '.dll', '.png', '.jpg']
        if extension in skip_exts:
            return [0, 0, extension, 0]

        # --- Step 3: Read Binary Data ---
        with open(file_path, 'rb') as f:
            data = f.read()
            
        if not data:
            return [0, 0, extension, 0]

        # --- Step 4: Shannon Entropy Calculation ---
        # Calculates the randomness of data. 
        # High entropy (> 7.0) often indicates packed/compressed malware or encrypted payloads.
        file_len = len(data)
        byte_counts = Counter(data)
        entropy = 0
        for count in byte_counts.values():
            p_x = count / file_len
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        
        # --- Step 5: Suspicious Keyword Analysis ---
        # Search for Indicators of Compromise (IOCs) in the raw binary data.
        suspicious_keywords = [
            b'eval(', b'document.write(', b'base64_decode', b'unescape(', 
            b'frombase64string', b'charcodeat', b'xor',
            b'powershell', b'-nop', b'-enc', b'bypass', b'hidden', 
            b'invoke-expression', b'iex', b'downloadstring', b'downloadfile',
            b'cmd.exe', b'/c', b'wscript.shell', b'shell.application',
            b'rundll32', b'regsvr32', b'bitsadmin', b'certutil',
            b'wget', b'curl', b'httprequest', b'socket', b'tcpclient',
            b'shellcode', b'inject', b'payload', b'reverse_tcp', b'metasploit',
            b'keylogger', b'hook',
            b'bitcoin', b'monero', b'wallet', b'encrypt', b'ransom'
        ]
        
        keyword_hits = 0
        lower_data = data.lower()
        
        # Only perform deep keyword search on files smaller than 10MB to maintain speed.
        if file_size < 10 * 1024 * 1024:
            for key in suspicious_keywords:
                if key in lower_data:
                    keyword_hits += 1

        return [entropy, file_size, extension, keyword_hits]

    except Exception as e:
        # Return None if file access fails (e.g., permission denied)

        return None
