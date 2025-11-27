#!/bin/bash

# PhishGuard Extension Setup Script for macOS/Linux
echo "Starting PhishGuard Extension setup..."

# Check if Python is installed
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
else
    echo "Error: Python is not installed. Please install Python 3.6 or higher."
    exit 1
fi

echo "Using Python command: $PYTHON_CMD"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    $PYTHON_CMD -m venv venv
    if [ $? -ne 0 ]; then
        echo "Error: Failed to create virtual environment. Make sure 'venv' module is available."
        exit 1
    fi
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing required packages..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "Warning: Failed to install some dependencies from requirements.txt."
    echo "Trying to use dependencies.txt instead..."
    pip install -r dependencies.txt
    if [ $? -ne 0 ]; then
        echo "Warning: Failed to install dependencies from dependencies.txt."
        echo "You may need to install dependencies manually."
    fi
fi

# Ensure python-dotenv is installed
echo "Installing python-dotenv..."
pip install python-dotenv
if [ $? -ne 0 ]; then
    echo "Error: Failed to install python-dotenv. Please install it manually: pip install python-dotenv"
    exit 1
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env file..."
    cat > .env << EOL
# PhishGuard Environment Configuration

# VirusTotal API Keys (comma-separated if multiple)
# VIRUSTOTAL_API_KEYS=your_api_key1,your_api_key2

# Secret key for Flask sessions
SESSION_SECRET=phishguard_development_secret_key
EOL
    echo "Created .env file with default configuration"
fi

echo "Setup completed successfully!"
echo ""
echo "To start the application, run:"
echo "./scripts/run.sh"
echo ""
echo "To set up the Chrome extension:"
echo "1. Open Chrome and go to chrome://extensions/"
echo "2. Enable 'Developer mode' (toggle in top right)"
echo "3. Click 'Load unpacked' and select the 'extension' folder from this repository"