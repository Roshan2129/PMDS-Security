import logging
import requests
from urllib.parse import urlparse
from datetime import datetime, timedelta
from backend.models import ApiKeyUsage
from backend.database import db

logger = logging.getLogger(__name__)

def extract_domain(url):
    """Extract domain from URL"""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Handle cases where netloc is empty
        if not domain and parsed_url.path:
            # Try to parse URLs like "example.com/path"
            parts = parsed_url.path.split('/', 1)
            if '.' in parts[0]:
                domain = parts[0]
        
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        return domain
    except Exception as e:
        logger.error(f"Error extracting domain from {url}: {str(e)}")
        return ""

def get_next_api_key(app):
    """Get the next available API key using rotation strategy"""
    api_keys = app.config.get("VIRUSTOTAL_API_KEYS", [])
    
    if not api_keys:
        logger.error("No API keys configured")
        return None, None
    
    # Reset rate limits for keys that haven't been used in the last 1 minute
    reset_time = datetime.utcnow() - timedelta(minutes=1)
    db.session.query(ApiKeyUsage).filter(
        ApiKeyUsage.is_rate_limited == True,
        ApiKeyUsage.last_used < reset_time
    ).update({"is_rate_limited": False})
    db.session.commit()
    
    # Get all key usage records
    key_usage = {k.api_key: k for k in ApiKeyUsage.query.all()}
    
    # Check if we need to create records for new keys
    for api_key in api_keys:
        if api_key not in key_usage:
            usage = ApiKeyUsage(api_key=api_key)
            db.session.add(usage)
            key_usage[api_key] = usage
    
    db.session.commit()
    
    # Find the next available key that isn't rate limited
    for api_key in api_keys:
        usage = key_usage.get(api_key)
        if usage and not usage.is_rate_limited:
            return api_key, usage
    
    # All keys are rate limited
    logger.warning("All API keys are currently rate limited")
    return None, None

def is_url_safe(url, app):
    """Check if a URL is safe by checking blacklist, whitelist, and VirusTotal"""
    # Implementation would be similar to scan_url endpoint but simplified
    # for internal use. This is a placeholder for the actual implementation.
    return True, "Safe"

def validate_api_key(api_key):
    """Validate a VirusTotal API key by making a simple request"""
    try:
        # Make a simple request to the VirusTotal API to check if the key is valid
        headers = {
            "x-apikey": api_key
        }
        
        # Use a simple endpoint that doesn't consume quota
        response = requests.get("https://www.virustotal.com/api/v3/users/current", headers=headers)
        
        # Check response code
        if response.status_code == 200:
            return True, "API key is valid"
        elif response.status_code == 401:
            return False, "API key is invalid (authentication error)"
        elif response.status_code == 403:
            return False, "API key does not have sufficient permissions"
        else:
            return False, f"Unexpected response from VirusTotal: {response.status_code}"
            
    except Exception as e:
        logger.exception(f"Error validating API key: {str(e)}")
        return False, f"Error: {str(e)}"
