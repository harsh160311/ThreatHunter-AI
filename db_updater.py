import requests
import zipfile
import io
import csv
import json
import os

# 👇 PASTE YOUR API KEY HERE
API_KEY = "d4b6727d38221344ed644c69a53d29863437d200183e224c" 

def update_database():
    """
    Downloads the latest malware signatures from MalwareBazaar and updates the JSON database.
    """
    print("🔄 Connecting to Database...")

    url = "https://mb-api.abuse.ch/files/exports/recent.csv"
    # Sending API key via parameters is required for file downloads
    parameters = {"auth-key": API_KEY} 
    
    try:
        response = requests.get(url, params=parameters)
        
        if response.status_code == 200:
            print("✔ Download Successful! Processing data...")
            
            # Unzip if the server sends a zip file
            try:
                with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                    z.extractall(".") 
                    print("✔ File Unzipped: recent.csv")
            except:
                with open("recent.csv", "wb") as f:
                    f.write(response.content)
                print("✔ File Saved: recent.csv")

            # Convert CSV to JSON
            process_csv_to_json("recent.csv")
            
        else:
            print(f"❌ Error: Server returned status {response.status_code}")
            print("Reason: Invalid API Key or Server Restriction.")

    except Exception as e:
        print(f"❌ Connection Failed: {e}")

def process_csv_to_json(csv_file):
    json_file = "malware_db.json"
    new_signatures = {}
    
    # Load existing database to avoid overwriting old custom signatures
    if os.path.exists(json_file):
        with open(json_file, "r") as f:
            try:
                new_signatures = json.load(f)
            except:
                new_signatures = {}

    print(f"📂 Converting {csv_file} to Database...")
    count = 0
    
    try:
        with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                # Skip comments and metadata headers
                if not row or row[0].startswith("#"):
                    continue
                
                try:
                    sha256 = row[1]
                    sig = row[4]
                    
                    if not sig or sig == "n/a":
                        sig = "Malware: Unknown Variant"
                    
                    new_signatures[sha256] = f"Threat: {sig}"
                    count += 1
                except:
                    continue

        with open(json_file, "w") as f:
            json.dump(new_signatures, f, indent=4)
            
        print(f"✅ UPDATE COMPLETE!")
        print(f"🔥 Added {count} new threats from Cloud.")
        print(f"📚 Total Database Size: {len(new_signatures)} signatures.")
        
        if os.path.exists(csv_file):
            os.remove(csv_file)
            print("🧹 Cleaned up temporary CSV file.")

    except Exception as e:
        print(f"❌ Processing Error: {e}")

if __name__ == "__main__":
    update_database()