import os
import hashlib
import json

class USBSentryBrain:
    def __init__(self):
        self.signature_mapping = {
            "pdf": b"%PDF", "docx": b"PK\x03\x04", "png": b"\x89PNG",
            "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff",
            "exe": b"MZ", "dll": b"MZ", "bat": b"@", "ps1": b"#"
        }
        self.sig_db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "signatures.json"))

    def calculate_threat_score(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                content = f.read(2048) # Read header
            
            # Get the real extension
            ext = file_path.split('.')[-1].lower()

            # LAYER 1: EICAR VIRUS
            if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in content:
                return 100, "Malware", "Extreme", "EICAR Test Virus Found"

            # LAYER 2: DFA HEADER MISMATCH (SPOOFING)
            if ext in self.signature_mapping:
                expected = self.signature_mapping[ext]
                if expected and not content.startswith(expected):
                    return 85, "Spoofed File", "High", f"Header mismatch for .{ext}"

            # LAYER 3: EXTENSIBLE FILES (The Teacher's Requirement)
            if ext in ['exe', 'bat', 'vbs', 'ps1', 'msi', 'scr']:
                return 60, "Extensible Code", "Medium", "Active script/executable detected"

            return 0, "Verified", "Low", "No threats detected"
        except:
            return 0, "Unscannable", "Review", "Access denied"