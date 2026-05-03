import wmi, os, subprocess, time
from brain import USBSentryBrain
from database import init_db, log_event

def set_forensic_lock(drive, lock=True):
    mode = "+r" if lock else "-r"
    subprocess.run(['attrib', mode, f"{drive}\\*", '/s', '/d'], capture_output=True)

def get_usb_drive():
    c = wmi.WMI()
    for disk in c.Win32_LogicalDisk(DriveType=2):
        return disk.DeviceID
    return None

def start_gatekeeper():
    brain = USBSentryBrain()
    c = wmi.WMI()
    watcher = c.watch_for(notification_type="Creation", wmi_class="Win32_USBHub")

    print("====================================================")
    print("      SENTINEL USB: MULTI-LAYER AUDIT ACTIVE        ")
    print("====================================================")

    while True:
        try:
            watcher()
            time.sleep(2)
            drive = get_usb_drive()
            if drive:
                print(f"\n[!] SCANNING VOLUME {drive}...")
                total, threats = 0, 0

                for root, _, files in os.walk(drive + "\\"):
                    for f_name in files:
                        total += 1
                        path = os.path.join(root, f_name)
                        score, cat, label, adv = brain.calculate_threat_score(path)

                        if label == "Extreme":
                            threats += 1
                            print(f" [!!!] EXTREME: {f_name} ({adv})")
                        elif label == "High":
                            threats += 1
                            print(f"  [!] HIGH RISK: {f_name} (SPOOFED)")
                        elif label == "Medium":
                            threats += 1
                            print(f"  [-] SUSPICIOUS: {f_name} (EXTENSIBLE)")
                        else:
                            print(f"  [+] VERIFIED: {f_name}")
                        
                        log_event(drive, label, cat, score, f_name, adv)

                set_forensic_lock(drive, True)
                print(f"\nAUDIT COMPLETE. Threats: {threats}/{total}")
                print("====================================================")
        except Exception as e: print(f"Error: {e}")

if __name__ == "__main__":
    init_db()
    start_gatekeeper()