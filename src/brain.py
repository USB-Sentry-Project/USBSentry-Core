import os

class USBSentryBrain:
    def __init__(self):
        """
        The Brain performs Dual-Layer Verification:
        1. DFA Header Check (Structure)
        2. Signature Scanning (Content)
        """
        self.signature_mapping = {
            # Documents
            "pdf": b"%PDF",
            "docx": b"PK\x03\x04",
            "txt": b"", 
            # Images
            "png": b"\x89PNG",
            "jpg": b"\xff\xd8\xff",
            "jpeg": b"\xff\xd8\xff",
            # Executables
            "exe": b"MZ",
            "bat": b"@",
            # System Exceptions
            "fileid": b"", "dat": b"", "indexervolumeguid": b""
        }
        
        # Industry Standard Test Virus String (EICAR)
        # This is safe to use but recognized as 'Malicious' by security logic
        self.MALICIOUS_PAYLOAD = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    def verify_file_header(self, file_path, extension):
        ext = extension.lower().replace('.', '')
        if ext not in self.signature_mapping:
            return False
        
        expected = self.signature_mapping[ext]
        if expected == b"": # Trusted system metadata
            return True
            
        try:
            with open(file_path, "rb") as f:
                return f.read(len(expected)).startswith(expected)
        except:
            return False

    def scan_file_content(self, file_path):
        """
        Deep scan: Checks if the file contains the known malicious test string.
        """
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                return self.MALICIOUS_PAYLOAD in content
        except:
            return False