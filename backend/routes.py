import logging
import time
from datetime import datetime
from urllib.parse import urlparse, quote
import requests
from flask import request, jsonify, send_file
from backend.database import db
from backend.models import UrlScan, BlacklistEntry, WhitelistEntry, ApiKeyUsage, SystemSettings
from backend.utils import get_next_api_key, extract_domain, validate_api_key
from backend.report_generator import generate_report

logger = logging.getLogger(__name__)

def register_routes(app):
    @app.route("/")
    def index():
        return jsonify({"status": "Phishing Mail Detection System (PMDS) Backend is running"})

    @app.route("/scan_url", methods=["POST"])
    def scan_url():
        """Scan a URL for phishing indicators using VirusTotal API"""
        data = request.get_json()
        
        if not data or "url" not in data:
            return jsonify({"error": "URL is required"}), 400
        
        url = data.get("url")
        email_subject = data.get("email_subject", "")
        
        logger.debug(f"Received scan request for URL: {url}")
        
        # Extract domain from URL
        domain = extract_domain(url)
        
        # Check if URL or domain is in blacklist
        blacklist_check = BlacklistEntry.query.filter(
            (BlacklistEntry.pattern == url) |
            (BlacklistEntry.pattern == domain) & (BlacklistEntry.pattern_type == "domain")
        ).first()
        
        if blacklist_check:
            logger.info(f"URL {url} found in blacklist")
            # Save scan result
            scan = UrlScan(
                url=url,
                domain=domain,
                status="Suspicious", 
                detection_ratio="Blacklisted",
                email_subject=email_subject
            )
            db.session.add(scan)
            db.session.commit()
            
            return jsonify({
                "status": "Suspicious",
                "message": "URL is blacklisted",
                "scan_id": scan.id
            })
        
        # Check if URL or domain is in whitelist
        whitelist_check = WhitelistEntry.query.filter(
            (WhitelistEntry.pattern == url) |
            (WhitelistEntry.pattern == domain) & (WhitelistEntry.pattern_type == "domain")
        ).first()
        
        if whitelist_check:
            logger.info(f"URL {url} found in whitelist")
            # Save scan result
            scan = UrlScan(
                url=url,
                domain=domain,
                status="Safe", 
                detection_ratio="Whitelisted",
                email_subject=email_subject
            )
            db.session.add(scan)
            db.session.commit()
            
            return jsonify({
                "status": "Safe",
                "message": "URL is whitelisted",
                "scan_id": scan.id
            })
        
        # URL is neither blacklisted nor whitelisted, scan with VirusTotal
        api_key, key_obj = get_next_api_key(app)
        
        if api_key is None:
            logger.error("No available API keys to use")
            return jsonify({"error": "Service unavailable due to API rate limits"}), 503
        
        # Update API key usage
        if key_obj:
            key_obj.last_used = datetime.utcnow()
            key_obj.daily_usage += 1
            key_obj.monthly_usage += 1
            db.session.commit()
        
        try:
            # Call VirusTotal API
            headers = {
                "x-apikey": api_key
            }
            
            # First, check if URL already analyzed 
            report_url = f"https://www.virustotal.com/api/v3/urls/{quote(url, safe='')}"
            
            # Try to get existing report
            response = requests.get(report_url, headers=headers)
            
            # If URL hasn't been analyzed yet, submit it
            if response.status_code == 404:
                submit_url = "https://www.virustotal.com/api/v3/urls"
                params = {"url": url}
                response = requests.post(submit_url, data=params, headers=headers)
                
                if response.status_code == 200:
                    analysis_id = response.json().get("data", {}).get("id")
                    
                    # Wait a bit and poll for results
                    time.sleep(3)
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    response = requests.get(analysis_url, headers=headers)
                
            if response.status_code == 429:
                # Rate limited, mark the key
                if key_obj:
                    key_obj.is_rate_limited = True
                    db.session.commit()
                
                # Try with another key
                return scan_url()  # Recursively call the function to try again
            
            # Process response
            if response.status_code == 200:
                result = response.json()
                
                # Extract detection stats
                if "data" in result and "attributes" in result["data"]:
                    attributes = result["data"]["attributes"]
                    stats = attributes.get("last_analysis_stats", {})
                    
                    total = sum(stats.values())
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    
                    detection_ratio = f"{malicious + suspicious}/{total}"
                    
                    # Determine status based on detections
                    if malicious > 0:
                        status = "Phishing"
                    elif suspicious > 0:
                        status = "Suspicious"
                    else:
                        status = "Safe"
                    
                    # Save scan result
                    scan = UrlScan(
                        url=url,
                        domain=domain,
                        status=status, 
                        detection_ratio=detection_ratio,
                        email_subject=email_subject
                    )
                    db.session.add(scan)
                    db.session.commit()
                    
                    return jsonify({
                        "status": status,
                        "detection_ratio": detection_ratio,
                        "scan_id": scan.id
                    })
                else:
                    # Handle incomplete response
                    logger.warning(f"Incomplete response from VirusTotal: {result}")
                    
                    # Save as pending/unknown
                    scan = UrlScan(
                        url=url,
                        domain=domain,
                        status="Unknown", 
                        detection_ratio="0/0",
                        email_subject=email_subject
                    )
                    db.session.add(scan)
                    db.session.commit()
                    
                    return jsonify({
                        "status": "Unknown",
                        "message": "Unable to determine URL safety",
                        "scan_id": scan.id
                    })
            else:
                # Handle error response
                logger.error(f"Error from VirusTotal API: {response.status_code} - {response.text}")
                
                # Save as error
                scan = UrlScan(
                    url=url,
                    domain=domain,
                    status="Error", 
                    detection_ratio="API Error",
                    email_subject=email_subject
                )
                db.session.add(scan)
                db.session.commit()
                
                return jsonify({
                    "status": "Error",
                    "message": "Error scanning URL",
                    "scan_id": scan.id
                }), 500
                
        except Exception as e:
            logger.exception(f"Exception while scanning URL {url}: {str(e)}")
            return jsonify({"error": f"Exception: {str(e)}"}), 500

    @app.route("/get_dashboard_data", methods=["GET"])
    def get_dashboard_data():
        """Get dashboard data including recent scans, blacklist, and whitelist entries"""
        try:
            logger.info("Fetching dashboard data...")
            
            # Get recent scans (limit to 100)
            recent_scans = UrlScan.query.order_by(UrlScan.scan_date.desc()).limit(100).all()
            logger.debug(f"Found {len(recent_scans)} recent scans")
            
            # Get statistics
            total_scans = UrlScan.query.count()
            phishing_scans = UrlScan.query.filter_by(status="Phishing").count()
            suspicious_scans = UrlScan.query.filter_by(status="Suspicious").count()
            safe_scans = UrlScan.query.filter_by(status="Safe").count()
            logger.debug(f"Statistics: total={total_scans}, phishing={phishing_scans}, suspicious={suspicious_scans}, safe={safe_scans}")
            
            # Get blacklist entries
            blacklist = BlacklistEntry.query.all()
            logger.debug(f"Found {len(blacklist)} blacklist entries")
            
            # Get whitelist entries
            whitelist = WhitelistEntry.query.all()
            logger.debug(f"Found {len(whitelist)} whitelist entries")
            
            # Compile response
            response = {
                "recent_scans": [scan.to_dict() for scan in recent_scans],
                "statistics": {
                    "total_scans": total_scans,
                    "phishing_scans": phishing_scans,
                    "suspicious_scans": suspicious_scans,
                    "safe_scans": safe_scans
                },
                "blacklist": [entry.to_dict() for entry in blacklist],
                "whitelist": [entry.to_dict() for entry in whitelist]
            }
            
            logger.info("Dashboard data fetched successfully")
            return jsonify(response)
            
        except Exception as e:
            logger.exception(f"Exception in get_dashboard_data: {str(e)}")
            return jsonify({"error": f"Failed to load dashboard data: {str(e)}"}), 500

    @app.route("/manage_blacklist", methods=["POST", "DELETE"])
    def manage_blacklist():
        """Add or remove entries from blacklist"""
        if request.method == "POST":
            data = request.get_json()
            
            if not data or "pattern" not in data:
                return jsonify({"error": "Pattern is required"}), 400
            
            pattern = data.get("pattern")
            pattern_type = data.get("pattern_type", "url")
            notes = data.get("notes", "")
            
            try:
                # Check if entry already exists
                existing = BlacklistEntry.query.filter_by(pattern=pattern).first()
                if existing:
                    return jsonify({"error": "Entry already exists in blacklist"}), 409
                
                # Create new entry
                entry = BlacklistEntry(
                    pattern=pattern,
                    pattern_type=pattern_type,
                    notes=notes
                )
                db.session.add(entry)
                db.session.commit()
                
                return jsonify({"success": True, "entry": entry.to_dict()})
                
            except Exception as e:
                db.session.rollback()
                logger.exception(f"Exception adding to blacklist: {str(e)}")
                return jsonify({"error": f"Exception: {str(e)}"}), 500
                
        elif request.method == "DELETE":
            data = request.get_json()
            
            if not data or "id" not in data:
                return jsonify({"error": "Entry ID is required"}), 400
            
            entry_id = data.get("id")
            
            try:
                entry = BlacklistEntry.query.get(entry_id)
                
                if not entry:
                    return jsonify({"error": "Entry not found"}), 404
                
                db.session.delete(entry)
                db.session.commit()
                
                return jsonify({"success": True})
                
            except Exception as e:
                db.session.rollback()
                logger.exception(f"Exception removing from blacklist: {str(e)}")
                return jsonify({"error": f"Exception: {str(e)}"}), 500

    @app.route("/manage_whitelist", methods=["POST", "DELETE"])
    def manage_whitelist():
        """Add or remove entries from whitelist"""
        if request.method == "POST":
            data = request.get_json()
            
            if not data or "pattern" not in data:
                return jsonify({"error": "Pattern is required"}), 400
            
            pattern = data.get("pattern")
            pattern_type = data.get("pattern_type", "url")
            notes = data.get("notes", "")
            
            try:
                # Check if entry already exists
                existing = WhitelistEntry.query.filter_by(pattern=pattern).first()
                if existing:
                    return jsonify({"error": "Entry already exists in whitelist"}), 409
                
                # Create new entry
                entry = WhitelistEntry(
                    pattern=pattern,
                    pattern_type=pattern_type,
                    notes=notes
                )
                db.session.add(entry)
                db.session.commit()
                
                return jsonify({"success": True, "entry": entry.to_dict()})
                
            except Exception as e:
                db.session.rollback()
                logger.exception(f"Exception adding to whitelist: {str(e)}")
                return jsonify({"error": f"Exception: {str(e)}"}), 500
                
        elif request.method == "DELETE":
            data = request.get_json()
            
            if not data or "id" not in data:
                return jsonify({"error": "Entry ID is required"}), 400
            
            entry_id = data.get("id")
            
            try:
                entry = WhitelistEntry.query.get(entry_id)
                
                if not entry:
                    return jsonify({"error": "Entry not found"}), 404
                
                db.session.delete(entry)
                db.session.commit()
                
                return jsonify({"success": True})
                
            except Exception as e:
                db.session.rollback()
                logger.exception(f"Exception removing from whitelist: {str(e)}")
                return jsonify({"error": f"Exception: {str(e)}"}), 500

    @app.route("/manual_scan", methods=["POST"])
    def manual_scan():
        """Handle manual scan requests"""
        # This endpoint simply calls scan_url but logs that it was manually triggered
        data = request.get_json()
        
        if not data or "url" not in data:
            return jsonify({"error": "URL is required"}), 400
        
        logger.info(f"Manual scan triggered for URL: {data.get('url')}")
        
        # Delegate to scan_url
        return scan_url()

    @app.route("/settings", methods=["GET", "POST"])
    def settings():
        """Get or update system settings"""
        if request.method == "GET":
            try:
                settings = SystemSettings.query.all()
                return jsonify({
                    "settings": [setting.to_dict() for setting in settings]
                })
            except Exception as e:
                logger.exception(f"Exception getting settings: {str(e)}")
                return jsonify({"error": f"Exception: {str(e)}"}), 500
                
        elif request.method == "POST":
            data = request.get_json()
            
            if not data or "settings" not in data:
                return jsonify({"error": "Settings data is required"}), 400
            
            settings_data = data.get("settings")
            
            try:
                for setting_data in settings_data:
                    if "setting_name" not in setting_data or "setting_value" not in setting_data:
                        continue
                    
                    setting_name = setting_data.get("setting_name")
                    setting_value = setting_data.get("setting_value")
                    
                    # Find or create setting
                    setting = SystemSettings.query.filter_by(setting_name=setting_name).first()
                    
                    if setting:
                        # Update existing
                        setting.setting_value = setting_value
                    else:
                        # Create new
                        setting_type = setting_data.get("setting_type", "string")
                        setting = SystemSettings(
                            setting_name=setting_name,
                            setting_value=setting_value,
                            setting_type=setting_type
                        )
                        db.session.add(setting)
                
                db.session.commit()
                return jsonify({"success": True})
                
            except Exception as e:
                db.session.rollback()
                logger.exception(f"Exception updating settings: {str(e)}")
                return jsonify({"error": f"Exception: {str(e)}"}), 500
                
    @app.route("/api_keys", methods=["GET", "POST", "DELETE"])
    def manage_api_keys():
        """Get, add, or remove VirusTotal API keys"""
        if request.method == "GET":
            try:
                # Get all API key usage records
                keys = ApiKeyUsage.query.all()
                return jsonify({
                    "api_keys": [key.to_dict() for key in keys]
                })
            except Exception as e:
                logger.exception(f"Exception getting API keys: {str(e)}")
                return jsonify({"error": f"Exception: {str(e)}"}), 500
                
        elif request.method == "POST":
            data = request.get_json()
            
            if not data or "api_key" not in data:
                return jsonify({"error": "API key is required"}), 400
            
            api_key = data.get("api_key").strip()
            skip_validation = data.get("skip_validation", False)
            
            # Basic validation
            if len(api_key) < 16 and not skip_validation:
                return jsonify({"error": "API key seems too short to be valid"}), 400
                
            try:
                # Check if key already exists
                existing = ApiKeyUsage.query.filter_by(api_key=api_key).first()
                if existing:
                    return jsonify({"error": "This API key already exists"}), 409
                
                # If skip_validation is true, skip the actual API validation
                if skip_validation:
                    logger.warning("Skipping API key validation (for testing only)")
                    is_valid, message = True, "API key validation skipped (for testing only)"
                else:
                    # Validate the key against VirusTotal
                    is_valid, message = validate_api_key(api_key)
                
                if not is_valid:
                    return jsonify({"error": f"Invalid API key: {message}"}), 400
                
                # Create new key usage record
                key_usage = ApiKeyUsage(api_key=api_key)
                db.session.add(key_usage)
                db.session.commit()
                
                # Update the app config
                current_keys = app.config.get("VIRUSTOTAL_API_KEYS", [])
                if api_key not in current_keys:
                    current_keys.append(api_key)
                    app.config["VIRUSTOTAL_API_KEYS"] = current_keys
                
                return jsonify({"success": True, "key": key_usage.to_dict()})
                
            except Exception as e:
                db.session.rollback()
                logger.exception(f"Exception adding API key: {str(e)}")
                return jsonify({"error": f"Exception: {str(e)}"}), 500
                
        elif request.method == "DELETE":
            data = request.get_json()
            
            if not data or "id" not in data:
                return jsonify({"error": "Key ID is required"}), 400
            
            key_id = data.get("id")
            
            try:
                key_usage = ApiKeyUsage.query.get(key_id)
                
                if not key_usage:
                    return jsonify({"error": "API key not found"}), 404
                
                # Remove from app config
                current_keys = app.config.get("VIRUSTOTAL_API_KEYS", [])
                if key_usage.api_key in current_keys:
                    current_keys.remove(key_usage.api_key)
                    app.config["VIRUSTOTAL_API_KEYS"] = current_keys
                
                # Delete the record
                db.session.delete(key_usage)
                db.session.commit()
                
                return jsonify({"success": True})
                
            except Exception as e:
                db.session.rollback()
                logger.exception(f"Exception removing API key: {str(e)}")
                return jsonify({"error": f"Exception: {str(e)}"}), 500

    @app.route("/generate_report", methods=["GET"])
    def generate_report_endpoint():
        """Generate and download a report"""
        try:
            report_type = request.args.get("type", "scan_summary")
            start_date = request.args.get("start_date")
            end_date = request.args.get("end_date")
            
            # Generate the report
            report_file, filename = generate_report(report_type, start_date, end_date)
            
            # Send the file
            return send_file(
                report_file,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=filename
            )
            
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        except Exception as e:
            logger.exception(f"Exception generating report: {str(e)}")
            return jsonify({"error": f"Exception: {str(e)}"}), 500
