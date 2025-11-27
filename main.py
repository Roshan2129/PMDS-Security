import os

# Try to load environment variables from .env file if it exists
try:
    from dotenv import load_dotenv
    if os.path.exists('.env'):
        load_dotenv('.env')
except ImportError:
    print("Note: python-dotenv package not installed. Skipping .env file loading.")
    print("To install: pip install python-dotenv")

from backend.app import app

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)