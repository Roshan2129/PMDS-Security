#!/bin/bash

# PhishGuard Extension Run Script for macOS/Linux
echo "Starting PhishGuard Extension backend server..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run setup.sh first."
    exit 1
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Load environment variables from .env file
if [ -f ".env" ]; then
    echo "Loading environment variables from .env file..."
    set -a
    source .env
    set +a
fi

# Start the server
echo "Starting server..."
python main.py

# The following code won't run unless the server is stopped
echo "Server stopped."