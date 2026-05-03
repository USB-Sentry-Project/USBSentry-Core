import sqlite3
import os

def view_audit_trail():
    db_path = "usb_sentry_forensics.db"
    
    if not os.path.exists(db_path):
        print("\n[!] No Forensic Vault found. Run the Interceptor first to generate logs.")
        return

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Added ORDER BY id ASC to ensure serial numbers are perfectly in order
        cursor.execute("SELECT id, timestamp, device_id, action_taken, details FROM audit_logs ORDER BY id ASC")
        rows = cursor.fetchall()

        print("\n" + "="*100)
        print(f"{'ID':<4} | {'TIMESTAMP':<20} | {'ACTION':<15} | {'DETAILS'}")
        print("-" * 100)

        if not rows:
            print("No logs found in the Forensic Vault.")
        else:
            for row in rows:
                log_id, ts, dev_id, action, details = row
                # Clean up timestamp display
                clean_ts = ts.split(".")[0] 
                print(f"{log_id:<4} | {clean_ts:<20} | {action:<15} | {details}")

        print("="*100)
        print(f"Total Forensic Records: {len(rows)}")
        conn.close()

    except Exception as e:
        print(f"Error reading Forensic Vault: {e}")

if __name__ == "__main__":
    view_audit_trail()