import os
import logging

from flask import Flask
from flask_cors import CORS

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "phishing_detection_secret_key")

# Enable CORS for Chrome extension
CORS(app, resources={r"/*": {"origins": "*"}})

# Configure the database to use SQLite
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///phishing_detection.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Import and initialize db
from backend.database import db
db.init_app(app)

# Create the tables
with app.app_context():
    # Import models inside app context to avoid circular imports
    from backend.models import UrlScan, BlacklistEntry, WhitelistEntry, ApiKeyUsage, SystemSettings
    from backend.routes import register_routes
    
    db.create_all()
    register_routes(app)
    
    logger.info("Database tables created successfully")

# VirusTotal API keys
api_keys_env = os.environ.get("VIRUSTOTAL_API_KEYS", "")
app.config["VIRUSTOTAL_API_KEYS"] = [k.strip() for k in api_keys_env.split(",") if k.strip()]

# Load API keys from database
with app.app_context():
    from backend.models import ApiKeyUsage
    db_keys = ApiKeyUsage.query.all()
    
    if db_keys:
        # If we have keys in the database, use those instead of environment keys
        app.config["VIRUSTOTAL_API_KEYS"] = [k.api_key for k in db_keys]
        logger.info(f"Loaded {len(db_keys)} API keys from the database")
    elif not app.config["VIRUSTOTAL_API_KEYS"]:
        # If we don't have any keys, add placeholder keys for development
        logger.warning("No VirusTotal API keys found. Add API keys in the dashboard.")
        app.config["VIRUSTOTAL_API_KEYS"] = []

# Validate and initialize API keys
with app.app_context():
    from backend.utils import validate_api_key
    from backend.models import ApiKeyUsage
    
    # Initialize database records for new keys from environment
    db_keys = {k.api_key: k for k in ApiKeyUsage.query.all()}
    
    for key in app.config["VIRUSTOTAL_API_KEYS"]:
        if key not in db_keys and key != "":
            # Attempt to validate the key
            is_valid, message = validate_api_key(key)
            
            if is_valid:
                logger.info(f"Adding validated API key to database")
                key_usage = ApiKeyUsage(api_key=key)
                db.session.add(key_usage)
                db.session.commit()
            else:
                logger.warning(f"Invalid API key: {message}")
    
    # Report on available keys
    valid_keys = ApiKeyUsage.query.filter_by(is_rate_limited=False).count()
    logger.info(f"API key status: {valid_keys} valid keys available")
