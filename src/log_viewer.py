import sqlite3
import os
from database import DB_PATH  # This now points to the absolute path in /src

def view_forensic_vault():
    if not os.path.exists(DB_PATH):
        print("\n""[!] No logs found. Run a scan first.")
        return

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Pulling the full history from the permanent database
        cursor.execute("SELECT id, timestamp, file_name, threat_level, score, advice FROM scan_logs ORDER BY id ASC")
        rows = cursor.fetchall()

        if not rows:
            print("\n[!] The Forensic Vault is currently empty.")
        else:
            print(f"\n{'='*100}")
            print(f"{'ID':<5} | {'TIMESTAMP':<20} | {'FILE NAME':<30} | {'THREAT':<10} | {'SCORE':<7} | {'ADVICE'}")
            print(f"{'-'*100}")
            for row in rows:
                print(f"{row[0]:<5} | {row[1]:<20} | {row[2]:<30} | {row[3]:<10} | {row[4]:<7} | {row[5]}")
            print(f"{'='*100}\n")

        conn.close()
    except Exception as e:
        print(f"[!] Error accessing the vault: {e}")

if __name__ == "__main__":
    view_forensic_vault()