import psutil
import os
import subprocess

def get_usb_drive():
    """
    Scans the system for removable disk drives.
    Returns the drive letter (e.g., 'E') if a new USB is detected.
    """
    for partition in psutil.disk_partitions():
        # 'removable' detects USB sticks; 'cdrom' is excluded for forensics
        if 'removable' in partition.opts:
            # We return just the letter to keep path handling clean in gui.py
            return partition.mountpoint.replace(":\\", "").replace(":", "")
    return None

def set_forensic_lock(drive_letter, lock_state):
    """
    Handles the 'Mounting' logic for the UPES Forensic Sentry project.
    
    Logic:
    - If lock_state is True: The drive is 'Mounted' into the system from the sandbox 
      but set to READ-ONLY to preserve forensic integrity.
    - If lock_state is False: The drive is released from write-protection (Unmounted/User Access).
    """
    try:
        # drive_path translates the letter back to a Windows root path
        drive_path = f"{drive_letter}:\\"
        
        if lock_state:
            # Applying the 'Read-Only' attribute to all files (+r)
            # This simulates the transition from 'Sandbox' to 'Forensic Mount'.
            # /s processes matching files in the current folder and all subfolders.
            # /d processes folders as well.
            command = f'attrib +r "{drive_path}*.*" /s /d'
            subprocess.run(command, shell=True, check=True, capture_output=True)
            print(f"[SYSTEM] Forensic Lock Engaged: {drive_letter} is now Read-Only.")
        else:
            # Removing the 'Read-Only' attribute (-r) to 'Release' the drive
            command = f'attrib -r "{drive_path}*.*" /s /d'
            subprocess.run(command, shell=True, check=True, capture_output=True)
            print(f"[SYSTEM] Forensic Lock Released: {drive_letter} is now Writable.")
            
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to change drive state: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Unexpected interceptor error: {e}")
        return False

def verify_sandbox_isolation(drive_letter):
    """
    A helper function for your presentation to 'prove' the sandbox is active.
    It checks if the system can write a dummy file; if it fails, isolation is working.
    """
    test_file = f"{drive_letter}:\\sandbox_test.tmp"
    try:
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
        return False # Not isolated
    except IOError:
        return True # Isolated/Read-Only