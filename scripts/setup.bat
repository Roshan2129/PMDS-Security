@echo off
REM PhishGuard Extension Setup Script for Windows

echo Starting PhishGuard Extension setup...

REM Check if Python is installed
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: Python is not installed. Please install Python 3.6 or higher.
    exit /b 1
)

echo Using Python command: python

REM Create virtual environment if it doesn't exist
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo Error: Failed to create virtual environment. Make sure 'venv' module is available.
        exit /b 1
    )
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing required packages...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Warning: Failed to install some dependencies from requirements.txt.
    echo Trying to use dependencies.txt instead...
    pip install -r dependencies.txt
    if %errorlevel% neq 0 (
        echo Warning: Failed to install dependencies from dependencies.txt.
        echo You may need to install dependencies manually.
    )
)

REM Ensure python-dotenv is installed
echo Installing python-dotenv...
pip install python-dotenv
if %errorlevel% neq 0 (
    echo Error: Failed to install python-dotenv. Please install it manually: pip install python-dotenv
    exit /b 1
)

REM Create .env file if it doesn't exist
if not exist .env (
    echo Creating .env file...
    (
        echo # PhishGuard Environment Configuration
        echo.
        echo # VirusTotal API Keys (comma-separated if multiple)
        echo # VIRUSTOTAL_API_KEYS=your_api_key1,your_api_key2
        echo.
        echo # Secret key for Flask sessions
        echo SESSION_SECRET=phishguard_development_secret_key
    ) > .env
    echo Created .env file with default configuration
)

echo Setup completed successfully!
echo.
echo To start the application, run:
echo run.bat
echo.
echo To set up the Chrome extension:
echo 1. Open Chrome and go to chrome://extensions/
echo 2. Enable 'Developer mode' (toggle in top right)
echo 3. Click 'Load unpacked' and select the 'extension' folder from this repository