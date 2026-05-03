import os
import hashlib
import json

class USBSentryBrain:
    def __init__(self):
        """
        The Brain performs Multi-Layer Threat Classification:
        1. Signature Lookup (Known Malicious Hashes)
        2. DFA Header Verification (Structural Integrity)
        3. Extension Analysis (Suspicious File Types)
        """
        # Mapping for DFA Header Check
        self.signature_mapping = {
            "pdf": b"%PDF",
            "docx": b"PK\x03\x04",
            "png": b"\x89PNG",
            "jpg": b"\xff\xd8\xff",
            "jpeg": b"\xff\xd8\xff",
            "exe": b"MZ",
            "dll": b"MZ",
            "zip": b"PK\x03\x04",
            "rar": b"Rar!",
            "bat": b"@",
            "ps1": b"#",
            "vbs": b"'"
        }
        
        # This looks one folder 'up' from src to find signatures.json in the root
        self.sig_db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "signatures.json"))

    def calculate_threat_score(self, file_path):
        """
        Calculates a risk percentage and classifies the threat.
        """
        score = 0
        category = "General File"
        findings = []
        extension = os.path.splitext(file_path)[1].lower().replace('.', '')

        try:
            # We open the file in 'rb' mode. 
            # Note: The forensic lock in interceptor.py makes files Read-Only.
            # Python can still read them as long as we don't try to write.
            if not os.path.exists(file_path):
                return 0, "File Missing", "Review", "Path not found"

            with open(file_path, 'rb') as f:
                # Read first 1MB for hash and header to save memory and bypass some locks
                file_content = f.read(1024 * 1024) 
            
            # 1. Digital Fingerprint (MD5 Hash)
            file_hash = hashlib.md5(file_content).hexdigest()

            # Check signatures.json for known malware
            if os.path.exists(self.sig_db_path):
                with open(self.sig_db_path, 'r') as f:
                    db = json.load(f)
                    for malware in db.get('malware_signatures', []):
                        if file_hash == malware['hash']:
                            return 100, malware['category'], "Extreme", f"Match: {malware['name']}"

            # 2. DFA Header Verification
            if extension in self.signature_mapping:
                expected_header = self.signature_mapping[extension]
                if expected_header != b"":
                    if not file_content.startswith(expected_header):
                        # High threat because the file is pretending to be something else
                        return 80, "Spoofed/Mismatch", "High", "DFA Mismatch: Content does not match extension."

            # 3. Suspicious Extension Analysis (The 'Extensibles')
            if extension in ['exe', 'bat', 'scr', 'vbs', 'js', 'jar', 'ps1', 'dll']:
                score += 40
                findings.append("Executable Code")
                category = "Extensible/Active Code"

            # 4. EICAR Test String (Industry Standard)
            if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in file_content:
                return 100, "Test Virus", "Extreme", "EICAR Signature Found"

        except PermissionError:
            return 0, "Access Denied", "Review", "File is locked by OS or Forensic Lock."
        except Exception as e:
            return 0, "Scan Error", "Review", f"Error: {str(e)}"

        # Final Classification Logic
        if score >= 80:
            label = "High"
            advice = "Forensic Alert: Highly suspicious file structure."
        elif score >= 40:
            label = "Medium"
            advice = "Warning: Extensible file detected. Do not run unless trusted."
        else:
            label = "Low"
            category = "Verified" if extension in self.signature_mapping else "General"
            advice = "Safe: No immediate threats detected."

        return score, category, label, advice