from datetime import datetime
from backend.database import db

class UrlScan(db.Model):
    """Model for storing URL scan results"""
    __tablename__ = 'url_scan'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=False)
    domain = db.Column(db.String(255))
    status = db.Column(db.String(20), nullable=False)  # "Safe", "Suspicious", "Phishing"
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    detection_ratio = db.Column(db.String(20), nullable=True)  # e.g., "3/68"
    email_subject = db.Column(db.String(255), nullable=True)
    
    def to_dict(self):
        return {
            "id": self.id,
            "url": self.url,
            "domain": self.domain,
            "status": self.status,
            "scan_date": self.scan_date.strftime("%Y-%m-%d %H:%M:%S"),
            "detection_ratio": self.detection_ratio,
            "email_subject": self.email_subject
        }

class BlacklistEntry(db.Model):
    """Model for blacklisted domains or URLs"""
    __tablename__ = 'blacklist_entry'
    id = db.Column(db.Integer, primary_key=True)
    pattern = db.Column(db.String(2048), nullable=False, unique=True)
    pattern_type = db.Column(db.String(20), nullable=False)  # "domain" or "url"
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)
    
    def to_dict(self):
        return {
            "id": self.id,
            "pattern": self.pattern,
            "pattern_type": self.pattern_type,
            "date_added": self.date_added.strftime("%Y-%m-%d %H:%M:%S"),
            "notes": self.notes
        }

class WhitelistEntry(db.Model):
    """Model for whitelisted domains or URLs"""
    __tablename__ = 'whitelist_entry'
    id = db.Column(db.Integer, primary_key=True)
    pattern = db.Column(db.String(2048), nullable=False, unique=True)
    pattern_type = db.Column(db.String(20), nullable=False)  # "domain" or "url"
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)
    
    def to_dict(self):
        return {
            "id": self.id,
            "pattern": self.pattern,
            "pattern_type": self.pattern_type,
            "date_added": self.date_added.strftime("%Y-%m-%d %H:%M:%S"),
            "notes": self.notes
        }

class ApiKeyUsage(db.Model):
    """Model for tracking API key usage"""
    __tablename__ = 'api_key_usage'
    id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(64), nullable=False)
    last_used = db.Column(db.DateTime, default=datetime.utcnow)
    daily_usage = db.Column(db.Integer, default=0)
    monthly_usage = db.Column(db.Integer, default=0)
    is_rate_limited = db.Column(db.Boolean, default=False)
    
    def to_dict(self):
        return {
            "id": self.id,
            "api_key_prefix": self.api_key[:4] + "..." if len(self.api_key) > 4 else self.api_key,
            "last_used": self.last_used.strftime("%Y-%m-%d %H:%M:%S"),
            "daily_usage": self.daily_usage,
            "monthly_usage": self.monthly_usage,
            "is_rate_limited": self.is_rate_limited
        }

class SystemSettings(db.Model):
    """Model for system settings"""
    __tablename__ = 'system_settings'
    id = db.Column(db.Integer, primary_key=True)
    setting_name = db.Column(db.String(100), nullable=False, unique=True)
    setting_value = db.Column(db.String(255), nullable=True)
    setting_type = db.Column(db.String(20), nullable=False)  # "string", "boolean", "number"
    
    def to_dict(self):
        return {
            "id": self.id,
            "setting_name": self.setting_name,
            "setting_value": self.setting_value,
            "setting_type": self.setting_type
        }
