import sqlite3
import os

# This logic ensures the database file is always created in the same 
# folder as this script (the 'src' directory), which fixes pathing errors.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'usb_sentry_forensics.db')

def init_db():
    """
    Initializes the local SQLite database and creates the forensic 
    log table if it does not already exist.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # We include all forensic markers: timestamps, risk levels, and advice.
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_logs 
                    (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                     timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, 
                     device_id TEXT, 
                     threat_level TEXT, 
                     category TEXT, 
                     score REAL, 
                     file_info TEXT, 
                     advice TEXT)''')
    
    conn.commit()
    conn.close()
    print(f"[DATABASE] System initialized at: {DB_PATH}")

def log_event(device_id, threat_level, category, score, file_info, advice):
    """
    Records a forensic audit event into the database. 
    Standard SQLite CURRENT_TIMESTAMP handles the timing.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''INSERT INTO scan_logs 
                        (device_id, threat_level, category, score, file_info, advice) 
                        VALUES (?, ?, ?, ?, ?, ?)''', 
                        (device_id, threat_level, category, score, file_info, advice))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DATABASE ERROR] Failed to log event: {e}")

if __name__ == "__main__":
    # Manual initialization check
    init_db()