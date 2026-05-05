import os
import magic
import hashlib
import zipfile

class USBSentryBrain:
    def __init__(self):
        self.signature_mapping = {
            "pdf": b"%PDF", "docx": b"PK\x03\x04", "png": b"\x89PNG",
            "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff",
            "exe": b"MZ", "dll": b"MZ", "bat": b"@", "ps1": b"#"
        }

    def get_file_hash(self, file_path):
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except: return "Hash Unavailable"

    def calculate_threat_score(self, file_path):
        try:
            f_hash = self.get_file_hash(file_path)
            with open(file_path, 'rb') as f:
                content = f.read(8192) 
            
            filename = os.path.basename(file_path).lower()
            parts = filename.split('.')
            ext = parts[-1]
            actual_mime = magic.from_file(file_path, mime=True)

            # 1. MALWARE SIGNATURE (EXTREME)
            if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in content:
                return 100, "Malware", "Extreme", "EICAR Test Virus Found", actual_mime, f_hash

            # 2. REFINED DOUBLE EXTENSION LOGIC (FIX FOR WIRESHARK)
            # Only flag as Trojan Mask if a dangerous extension is hiding behind a "safe" fake one
            if len(parts) > 2:
                fake_ext = parts[-2]
                real_ext = parts[-1]
                dangerous = ['exe', 'bat', 'ps1', 'vbs', 'scr']
                spoof_targets = ['pdf', 'jpg', 'png', 'docx', 'txt', 'zip']
                
                if fake_ext in spoof_targets and real_ext in dangerous:
                    return 98, "Trojan Mask", "Extreme", f"Double Extension: {fake_ext} hidden as {real_ext}", actual_mime, f_hash

            # 3. ENCRYPTION DETECTION (REVIEW)
            is_protected = False
            if ext == 'pdf' and (b"/Encrypt" in content or b"/Standard" in content):
                is_protected = True
            elif ext == 'zip':
                try:
                    with zipfile.ZipFile(file_path) as zf:
                        for info in zf.infolist():
                            if info.flag_bits & 0x1:
                                is_protected = True; break
                except: is_protected = True
            elif ext in ['rar', '7z']:
                is_protected = True

            if is_protected:
                return 40, "Unscannable", "Review", "Password Protected: Forensic scan blocked.", actual_mime, f_hash

            # 4. SPOOFING (HIGH)
            if ext in self.signature_mapping:
                expected = self.signature_mapping[ext]
                if expected and not content.startswith(expected):
                    return 85, "Spoofed File", "High", f"Header mismatch: Extension .{ext} is actually {actual_mime}.", actual_mime, f_hash

            # 5. SCRIPT DETECTION (MEDIUM)
            if ext in ['exe', 'bat', 'vbs', 'ps1'] or 'x-msdos-batch' in actual_mime:
                return 58, "Executable File", "Medium", "Script detected. Verify source manually.", actual_mime, f_hash

            # 6. TRUSTED/CLEAN STATUS (LOW)
            clean_exts = ['txt', 'mp4', 'mp3', 'csv', 'xlsx', 'pptx', 'png', 'jpg', 'tar', 'gz']
            if ext in clean_exts:
                return 0, "Clean", "Low", "No immediate threats detected", actual_mime, f_hash

            # 7. UNKNOWN (REVIEW)
            if ext not in self.signature_mapping:
                return 40, "Unscannable", "Review", "Unknown Signature: Manual verification required.", actual_mime, f_hash
            
            return 0, "Clean", "Low", "No immediate threats detected", actual_mime, f_hash

        except Exception:
            return 40, "Unscannable", "Review", "Read Error: Manual check required.", "unknown", "N/A"