import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect("usb_sentry_forensics.db")
    cursor = conn.cursor()
    # We MUST have device_id in this CREATE statement
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            device_id TEXT,
            action_taken TEXT,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_event(device_id, action, details):
    conn = sqlite3.connect("usb_sentry_forensics.db")
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute('''
        INSERT INTO audit_logs (timestamp, device_id, action_taken, details)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, device_id, action, details))
    conn.commit()
    conn.close()