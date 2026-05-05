import sqlite3
import os

# Database is kept in the /src folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'usb_sentry_forensics.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_logs 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, 
                     device_id TEXT, 
                     file_name TEXT,
                     claimed_ext TEXT,
                     actual_mime TEXT,
                     threat_level TEXT, 
                     category TEXT, 
                     score REAL, 
                     file_size REAL,
                     advice TEXT,
                     access_count INTEGER DEFAULT 1)''')
    conn.commit()
    conn.close()
    
    # Always inserting new rows instead of updating,
    # so we keep full scan history for analysis

def log_event(device_id, file_name, claimed_ext, actual_mime, threat_level, category, score, file_size, advice):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # REMOVED THE "SELECT/UPDATE" LOGIC 
        # This force-inserts a NEW row for every single file scanned, every single time.
        cursor.execute('''INSERT INTO scan_logs 
                        (device_id, file_name, claimed_ext, actual_mime, threat_level, category, score, file_size, advice) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                        (device_id, file_name, claimed_ext, actual_mime, threat_level, category, score, file_size, advice))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DATABASE ERROR] {e}")