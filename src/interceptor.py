import wmi
import os
import subprocess
import time
from brain import USBSentryBrain
from database import init_db, log_event

def set_forensic_lock(drive_letter, lock=True):
    """
    Forensic Workaround: Sets all files on the USB to Read-Only 
    to prevent accidental execution or modification during scanning.
    """
    mode = "+r" if lock else "-r"
    try:
        # Using Windows attrib command to set Read-Only attribute
        subprocess.run(['attrib', mode, f"{drive_letter}\\*", '/s', '/d'], capture_output=True)
        status = "LOCKED (Read-Only)" if lock else "UNLOCKED (Read-Write)"
        print(f"[SYSTEM] USB Forensic State: {status}")
    except Exception as e:
        print(f"[!] Warning: Could not set forensic lock: {e}")

def get_usb_drive():
    c = wmi.WMI()
    # DriveType=2 identifies Removable Media (USB)
    for disk in c.Win32_LogicalDisk(DriveType=2):
        return disk.DeviceID
    return None

def start_gatekeeper():
    brain = USBSentryBrain()
    c = wmi.WMI()
    watcher = c.watch_for(notification_type="Creation", wmi_class="Win32_USBHub")

    print("====================================================")
    print("      SENTINEL USB: ADVANCED FORENSIC AUDIT         ")
    print("====================================================")

    while True:
        try:
            usb_device = watcher()
            device_id = usb_device.DeviceID
            
            # Allow time for drive mounting
            time.sleep(2)
            
            drive = get_usb_drive()
            if drive:
                print(f"\n[!] DEVICE DETECTED: {device_id}")
                print(f"Volume {drive} detected. Initializing Forensic Scan...")
                
                total_files = 0
                threat_count = 0

                # SCAN FIRST while files are accessible
                for root, dirs, files in os.walk(drive + "\\"):
                    for file_name in files:
                        total_files += 1
                        file_path = os.path.join(root, file_name)
                        
                        score, category, label, advice = brain.calculate_threat_score(file_path)
                        
                        # Standard terminal output
                        if label == "Extreme":
                            threat_count += 1
                            print(f"  [!!!] EXTREME: {file_name} (Known Malware)")
                        elif label == "High":
                            threat_count += 1
                            print(f"  [!] HIGH RISK: {file_name} (Header Mismatch)")
                        elif label == "Medium":
                            print(f"  [-] SUSPICIOUS: {file_name} (Active Code)")
                        else:
                            print(f"  [+] VERIFIED: {file_name}")

                        log_event(device_id, label, f"{category}: {file_name}")

                # APPLY LOCK AFTER SCAN to protect the system
                set_forensic_lock(drive, lock=True)

                print(f"\nAUDIT COMPLETE FOR {drive}:")
                print(f" - Scanned: {total_files} | High/Extreme Threats: {threat_count}")
                print("====================================================")

        except Exception as e:
            print(f"\n[ERROR] {e}")

if __name__ == "__main__":
    init_db()
    start_gatekeeper()