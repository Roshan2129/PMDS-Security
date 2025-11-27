@echo off
REM PhishGuard Extension Run Script for Windows

echo Starting PhishGuard Extension backend server...

REM Check if virtual environment exists
if not exist venv (
    echo Virtual environment not found. Please run setup.bat first.
    exit /b 1
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Load environment variables from .env file
if exist .env (
    echo Loading environment variables from .env file...
    for /f "tokens=*" %%a in (.env) do (
        set line=%%a
        if not "!line:~0,1!"=="#" (
            if not "!line!"=="" (
                set %%a
            )
        )
    )
)

REM Start the server
echo Starting server...
python main.py

REM The following code won't run unless the server is stopped
echo Server stopped.