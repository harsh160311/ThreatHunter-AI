@echo off
title ThreatHunter AI - System Diagnostic & Launcher
color 0b

echo ========================================================
echo       THREATHUNTER AI - DIAGNOSTIC LAUNCHER
echo ========================================================
echo.

:: --- STEP 1: CHECK PYTHON INSTALLATION ---
echo [*] Checking Python Installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERROR: Python is not detected!
    echo [i] Tip: Try reinstalling Python and check "Add to PATH".
    echo.
    pause
    exit
)
echo [OK] Python is installed.
echo.

:: --- STEP 2: INSTALL MISSING LIBRARIES ---
echo [*] Checking & Installing Dependencies...
echo     (This might take time if libraries are missing)
echo.
pip install PyQt5 scikit-learn requests joblib >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Warning: Could not install libraries automatically.
    echo [i] Check your internet connection.
) else (
    echo [OK] All required libraries are ready.
)
echo.

:: --- STEP 3: UPDATE DATABASE ---
echo [*] Phase 1: Updating Virus Database...
python db_updater.py
echo.

:: --- STEP 4: TRAIN MODEL ---
echo [*] Phase 2: Training AI Model...
python train_model.py
if %errorlevel% neq 0 (
    echo [!] Error in training model. Check 'train_model.py'.
    pause
    exit
)
echo [OK] Model Trained.
echo.

:: --- STEP 5: LAUNCH APP ---
echo [*] Phase 3: Launching Application...
echo ========================================================
echo     Running ThreatHunter AI...
echo ========================================================
python app.py

:: --- ERROR HANDLING ---
if %errorlevel% neq 0 (
    echo.
    echo [!!!!] CRITICAL ERROR [!!!!]
    echo The application crashed. Read the error message above.
    echo.
)

pause