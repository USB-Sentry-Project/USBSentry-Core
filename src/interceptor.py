import wmi
import os
from brain import USBSentryBrain
from database import init_db, log_event

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
    print("   USB SENTRY: DUAL-LAYER ADVANCED AUDIT MODE       ")
    print("====================================================")

    while True:
        try:
            usb_device = watcher()
            device_id = usb_device.DeviceID
            log_event(device_id, "ANALYZING", "DEEP_SCAN_INITIATED")
            
            drive = get_usb_drive()
            if drive:
                print(f"\nDEVICE DETECTED: {device_id}")
                print(f"Volume {drive} attached. Running Identity & Content Audit...")
                
                total_files = 0
                threats = 0

                for root, dirs, files in os.walk(drive):
                    for file_name in files:
                        total_files += 1
                        file_path = os.path.join(root, file_name)
                        extension = file_name.split('.')[-1].lower() if '.' in file_name else "none"
                        
                        # LAYER 1: DFA Header Verification
                        header_ok = brain.verify_file_header(file_path, extension)
                        
                        # LAYER 2: Malicious Signature Scanning
                        is_infected = brain.scan_file_content(file_path)
                        
                        if is_infected:
                            threats += 1
                            print(f"  [!!!] VIRUS DETECTED: {file_name} (Payload Signature Match)")
                            log_event(device_id, "MALWARE_BLOCKED", f"VIRUS: {file_name}")
                        elif not header_ok:
                            threats += 1
                            print(f"  [!] REJECTED: {file_name} (DFA Header Mismatch/Spoofing)")
                            log_event(device_id, "SPOOF_BLOCKED", f"FAKE_EXT: {file_name}")
                        else:
                            print(f"  [+] VERIFIED: {file_name}")
                            log_event(device_id, "VERIFIED", f"CLEAN: {file_name}")

                print(f"\nFINAL AUDIT SUMMARY:")
                print(f"    - Total Items Scanned: {total_files}")
                print(f"    - Malicious Threats: {threats}")
                print("====================================================")
            
        except Exception as e:
            print(f"\nError: {e}")

if __name__ == "__main__":
    init_db()
    start_gatekeeper()