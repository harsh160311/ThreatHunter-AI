# ==============================================================================
# 🛡️ ThreatHunter AI
# © 2026 Harsh (@harsh160311). All rights reserved.
# 
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.
# ==============================================================================
import joblib
import random
from sklearn.ensemble import RandomForestClassifier

# ==============================================================================
# STEP 1: SYNTHETIC DATA GENERATION
# ==============================================================================
data = []
labels = []

print(">>> Generating Synthetic Training Data...")

# 1. Safe Files (Low Entropy, Normal Sizes)
for _ in range(300):
    entropy = random.uniform(3.0, 5.2)
    size = random.randint(100, 100 * 1024) 
    keywords = random.randint(0, 1) 
    is_suspicious_ext = 0
    data.append([entropy, size, keywords, is_suspicious_ext])
    labels.append(0) 

# 2. Safe Installers (High Entropy, Large Size, No Keywords)
for _ in range(300):
    entropy = random.uniform(7.0, 7.99) 
    size = random.randint(15 * 1024 * 1024, 100 * 1024 * 1024) 
    keywords = 0
    is_suspicious_ext = 1 
    data.append([entropy, size, keywords, is_suspicious_ext])
    labels.append(0) 

# 3. Malware (Scripts: Low Entropy, High Keywords)
for _ in range(300):
    entropy = random.uniform(3.5, 5.5)
    size = random.randint(1 * 1024, 50 * 1024)
    keywords = random.randint(3, 15) 
    is_suspicious_ext = 1
    data.append([entropy, size, keywords, is_suspicious_ext])
    labels.append(1) 

# 4. Malware (Packed: High Entropy, Small Size)
for _ in range(300):
    entropy = random.uniform(7.2, 7.99) 
    size = random.randint(20 * 1024, 2 * 1024 * 1024) 
    keywords = 0
    is_suspicious_ext = 1
    data.append([entropy, size, keywords, is_suspicious_ext])
    labels.append(1) 

# ==============================================================================
# STEP 2: MODEL TRAINING
# ==============================================================================
print(f">>> Training Random Forest Classifier on {len(data)} samples...")

combined = list(zip(data, labels))
random.shuffle(combined)
data[:], labels[:] = zip(*combined)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(data, labels)

joblib.dump(clf, "malware_model.pkl")

print("✅ Success: 'malware_model.pkl' has been created.")
