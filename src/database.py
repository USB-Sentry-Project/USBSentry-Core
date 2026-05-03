import sqlite3
import os

DB_NAME = "usb_sentry_forensics.db"

def init_db():
    """Initializes the SQLite database with professional forensic columns."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Adding specific columns for Score, Category, and Advice
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            device_id TEXT,
            threat_level TEXT,
            category TEXT,
            score INTEGER,
            file_info TEXT,
            advice TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_event(device_id, level, category, score, file_info, advice):
    """Logs a detailed forensic record for the UPES project audit."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_logs (device_id, threat_level, category, score, file_info, advice)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (device_id, level, category, score, file_info, advice))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DATABASE ERROR] Failed to log forensic event: {e}")