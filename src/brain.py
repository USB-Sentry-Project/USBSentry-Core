import os
import magic
import hashlib

class USBSentryBrain:
    def __init__(self):
        self.signature_mapping = {
            "pdf": b"%PDF", "docx": b"PK\x03\x04", "png": b"\x89PNG",
            "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff",
            "exe": b"MZ", "dll": b"MZ", "bat": b"@", "ps1": b"#"
        }

    def get_file_hash(self, file_path):
        """Generates MD5 hash for forensic identification."""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return "Hash Unavailable"

    def get_actual_mime(self, file_path):
        try: return magic.from_file(file_path, mime=True)
        except: return "unknown/binary"

    def calculate_threat_score(self, file_path):
        try:
            f_hash = self.get_file_hash(file_path)
            with open(file_path, 'rb') as f:
                content = f.read(2048) 
            
            ext = file_path.split('.')[-1].lower()
            actual_mime = self.get_actual_mime(file_path)

            if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in content:
                return 100, "Malware", "Extreme", "EICAR Test Virus Found", actual_mime, f_hash

            if ext in self.signature_mapping:
                expected = self.signature_mapping[ext]
                if expected and not content.startswith(expected):
                    return 85, "Spoofed File", "High", f"Header mismatch for .{ext}", actual_mime, f_hash

            if ext in ['exe', 'bat', 'vbs', 'ps1', 'msi', 'scr']:
                return 60, "Extensible Code", "Medium", "Active script detected", actual_mime, f_hash

            return 0, "Verified", "Low", "No threats detected", actual_mime, f_hash
        except Exception as e:
            return 0, "Unscannable", "Review", f"Error: {str(e)}", "unknown", "N/A"