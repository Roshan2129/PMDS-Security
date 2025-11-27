# PMDS-Security
A Chrome extension that protects Gmail users from phishing attacks by scanning URLs and providing real-time alerts.

## Features
- Real-time scanning of URLs in Gmail messages
- Detection of phishing attempts using VirusTotal API
- Dashboard with scan history and statistics
- Blacklist and whitelist management
- API key management in dashboard settings
- Email content analysis (coming soon)
- Attachment scanning (coming soon)

## Easy Setup Instructions

### Quick Start (Using Setup Scripts)

1. Clone the repository:
```bash
git clone https://github.com/Roshan2129/PMDS-Security.git
cd PMDS-Security
```

2. Run the setup script:
```bash
# On Windows
setup.bat

# On macOS/Linux
chmod +x setup.sh
./setup.sh
```

3. Start the application:
```bash
# On Windows
run.bat

# On macOS/Linux
chmod +x run.sh
./run.sh
```

The backend will run at http://localhost:5000

### Manual Setup

1. Clone the repository:
```bash
git clone https://github.com/Roshan2129/PMDS-Security.git
cd PMDS-Security
```

2. Create and activate a virtual environment (recommended):
```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. Install the required dependencies:
```bash
# Option 1: Install from requirements.txt (if available)
pip install -r requirements.txt
pip install python-dotenv  # Required for loading environment variables

# Option 2: Install from dependencies.txt
pip install -r dependencies.txt
```

4. Set your VirusTotal API keys (optional - you can also add them later in the dashboard):
```bash
# On Windows
set VIRUSTOTAL_API_KEYS=your_api_key1,your_api_key2

# On macOS/Linux
export VIRUSTOTAL_API_KEYS=your_api_key1,your_api_key2
```

5. Run the backend server:
```bash
python main.py
```

   This will start the Flask server on `http://localhost:5000`. The extension is configured to connect to this URL by default.

### Chrome Extension Setup

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" (toggle switch in the top right)
3. Click "Load unpacked" and select the `extension` folder from this repository
4. The PhishGuard extension icon should now appear in your browser toolbar

### API Key Management

You can manage your VirusTotal API keys in two ways:

1. **Via Environment Variable**: Set the `VIRUSTOTAL_API_KEYS` environment variable with comma-separated API keys.
2. **Via Dashboard**: Navigate to Settings in the extension dashboard and add/remove API keys there.

If you don't have a VirusTotal API key, you can:
- Sign up for a free account at [VirusTotal](https://www.virustotal.com/gui/join-us)

## Project Structure

- `/backend` - Flask backend server for API processing
  - `app.py` - Main Flask application setup
  - `database.py` - Database connection and SQLAlchemy setup
  - `models.py` - Database models
  - `routes.py` - API endpoints
  - `utils.py` - Utility functions
- `/extension` - Chrome extension files
  - `/popup` - Extension popup
  - `/dashboard` - Dashboard UI
  - `/content` - Content scripts for Gmail integration
  - `background.js` - Background scripts
  - `manifest.json` - Extension configuration
- `/scripts` - Convenience scripts for setup and running

## Database

By default, the application uses SQLite with a local database file at `instance/phishing_detection.db`. The database is automatically created on first run.

If you wish to use PostgreSQL:
1. Install PostgreSQL
2. Set the `DATABASE_URL` environment variable to your PostgreSQL connection string:
```bash
# Example
export DATABASE_URL=postgresql://username:password@localhost/phishguard
```

## Troubleshooting

- **"Class already has a primary mapper defined"**: If you encounter this error when running the application locally, it's typically caused by circular imports. Try running with the provided scripts which use a stable configuration.

- **"No module named 'dotenv'"**: This error occurs when the python-dotenv package is not installed. Install it with `pip install python-dotenv`.

- **Connection Issues**: Make sure the backend is running at http://localhost:5000 before using the extension. Check your browser console for any connection errors.

- **"Error loading recent scans"**: This error in the browser console typically means the extension is trying to connect to the wrong port. The backend runs on port 5000 by default. If you've modified the port, you'll need to update the `API_BASE_URL` in the extension JavaScript files (popup.js, dashboard.js, content.js, and background.js).

- **API Key Validation Failures**: If you're having trouble validating your VirusTotal API key, you can temporarily use the "Skip validation" option in the dashboard, but remember this is only for testing.

- **Missing Dependencies**: If you encounter any module not found errors, make sure all requirements are installed with either `pip install -r requirements.txt` or `pip install -r dependencies.txt`.

## Development

To contribute or modify the extension:

1. Backend changes: Modify the Flask application in the `/backend` directory.
2. Frontend changes: Update the extension files in the `/extension` directory.
3. Test API endpoints using curl or a tool like Postman before integrating with the frontend.
