import os
from datetime import datetime, timedelta
from flask import send_file
from backend.models import UrlScan, BlacklistEntry, WhitelistEntry
from backend.database import db
import pandas as pd
import io

def generate_report(report_type, start_date=None, end_date=None):
    """
    Generate different types of reports based on the data
    Args:
        report_type (str): Type of report ('scan_summary', 'blacklist', 'whitelist')
        start_date (str): Start date in YYYY-MM-DD format
        end_date (str): End date in YYYY-MM-DD format
    Returns:
        BytesIO: Report file in memory
    """
    # Convert string dates to datetime objects
    if start_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
    if end_date:
        end_date = datetime.strptime(end_date, '%Y-%m-%d')
        # Add one day to include the end date
        end_date = end_date + timedelta(days=1)

    if report_type == 'scan_summary':
        # Query URL scans with date filter
        query = UrlScan.query
        if start_date:
            query = query.filter(UrlScan.scan_date >= start_date)
        if end_date:
            query = query.filter(UrlScan.scan_date < end_date)
        
        scans = query.all()
        
        # Create DataFrame
        data = []
        for scan in scans:
            data.append({
                'URL': scan.url,
                'Domain': scan.domain,
                'Status': scan.status,
                'Scan Date': scan.scan_date.strftime('%Y-%m-%d %H:%M:%S'),
                'Detection Ratio': scan.detection_ratio,
                'Email Subject': scan.email_subject
            })
        
        df = pd.DataFrame(data)
        
        # Generate Excel file
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Scan Summary', index=False)
            
            # Auto-adjust column widths
            worksheet = writer.sheets['Scan Summary']
            for i, col in enumerate(df.columns):
                max_length = max(df[col].astype(str).apply(len).max(), len(col)) + 2
                worksheet.set_column(i, i, max_length)
        
        output.seek(0)
        return output, 'scan_summary.xlsx'

    elif report_type == 'blacklist':
        # Query blacklist entries
        entries = BlacklistEntry.query.all()
        
        # Create DataFrame
        data = []
        for entry in entries:
            data.append({
                'Pattern': entry.pattern,
                'Type': entry.pattern_type,
                'Date Added': entry.date_added.strftime('%Y-%m-%d %H:%M:%S'),
                'Notes': entry.notes
            })
        
        df = pd.DataFrame(data)
        
        # Generate Excel file
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Blacklist', index=False)
            
            # Auto-adjust column widths
            worksheet = writer.sheets['Blacklist']
            for i, col in enumerate(df.columns):
                max_length = max(df[col].astype(str).apply(len).max(), len(col)) + 2
                worksheet.set_column(i, i, max_length)
        
        output.seek(0)
        return output, 'blacklist.xlsx'

    elif report_type == 'whitelist':
        # Query whitelist entries
        entries = WhitelistEntry.query.all()
        
        # Create DataFrame
        data = []
        for entry in entries:
            data.append({
                'Pattern': entry.pattern,
                'Type': entry.pattern_type,
                'Date Added': entry.date_added.strftime('%Y-%m-%d %H:%M:%S'),
                'Notes': entry.notes
            })
        
        df = pd.DataFrame(data)
        
        # Generate Excel file
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, sheet_name='Whitelist', index=False)
            
            # Auto-adjust column widths
            worksheet = writer.sheets['Whitelist']
            for i, col in enumerate(df.columns):
                max_length = max(df[col].astype(str).apply(len).max(), len(col)) + 2
                worksheet.set_column(i, i, max_length)
        
        output.seek(0)
        return output, 'whitelist.xlsx'

    else:
        raise ValueError(f"Invalid report type: {report_type}") 