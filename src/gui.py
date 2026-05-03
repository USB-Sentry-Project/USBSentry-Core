import tkinter as tk
from tkinter import ttk
import threading
import os
import pythoncom  # <--- NEW: Required for background threads to talk to Windows
# Importing your verified backend
from interceptor import get_usb_drive, set_forensic_lock
from brain import USBSentryBrain
from database import init_db, log_event

class USBSentryGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("USBSentry | Automated Forensics & Access Control")
        self.root.geometry("900x600")
        self.root.configure(bg="#f0f2f5")
        self.brain = USBSentryBrain()

        # 1. Professional Header
        self.header = tk.Frame(root, bg="#2c3e50", height=80)
        self.header.pack(fill=tk.X)
        
        tk.Label(self.header, text="🛡️ USBSentry Forensic Dashboard", 
                 font=("Segoe UI", 18, "bold"), fg="white", bg="#2c3e50").pack(pady=20)

        # 2. Status Area
        self.status_frame = tk.Frame(root, bg="#f0f2f5")
        self.status_frame.pack(pady=10)
        
        self.status_icon = tk.Label(self.status_frame, text="🔍", font=("Segoe UI", 24), bg="#f0f2f5")
        self.status_icon.grid(row=0, column=0, padx=10)
        
        self.status_text = tk.Label(self.status_frame, text="WAITING FOR USB DEVICE...", 
                                   font=("Segoe UI", 12), fg="#7f8c8d", bg="#f0f2f5")
        self.status_text.grid(row=0, column=1)

        # 3. Progress Bar
        self.progress = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=600, mode='determinate')
        self.progress.pack(pady=10)

        # 4. Results Table
        columns = ("File Name", "Risk Level", "Category", "Forensic Advice")
        self.tree = ttk.Treeview(root, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180)
        
        self.tree.pack(padx=30, pady=10, fill=tk.BOTH, expand=True)

        # Start Listener in a thread
        threading.Thread(target=self.monitor_usb, daemon=True).start()

    def monitor_usb(self):
        """Background thread to wait for USB."""
        import time
        # CRITICAL FIX: Tell Windows this thread will use COM objects (WMI)
        pythoncom.CoInitialize() 
        
        while True:
            drive = get_usb_drive()
            if drive:
                self.root.after(0, self.start_ui_scan, drive)
                self.run_forensic_scan(drive)
                break
            time.sleep(2)

    def start_ui_scan(self, drive):
        self.status_text.config(text=f"SCANNING VOLUME {drive}...", fg="#2980b9")
        self.status_icon.config(text="⚙️")
        self.tree.delete(*self.tree.get_children())

    def run_forensic_scan(self, drive):
        files_to_scan = []
        for root, _, files in os.walk(drive + "\\"):
            for f in files:
                files_to_scan.append(os.path.join(root, f))
        
        if not files_to_scan: return

        total = len(files_to_scan)
        for i, path in enumerate(files_to_scan):
            score, cat, label, adv = self.brain.calculate_threat_score(path)
            f_name = os.path.basename(path)
            
            # Update UI and Log
            self.root.after(0, self.update_table, f_name, label, cat, adv)
            self.progress['value'] = ((i + 1) / total) * 100
            log_event(drive, label, cat, score, f_name, adv)
        
        set_forensic_lock(drive, True)
        self.root.after(0, self.finish_ui_scan, total)

    def update_table(self, name, level, cat, adv):
        item = self.tree.insert("", tk.END, values=(name, level, cat, adv))
        # Tagging for colors
        if level == "Extreme": self.tree.item(item, tags=('extreme',))
        if level == "High": self.tree.item(item, tags=('high',))
        
        self.tree.tag_configure('extreme', foreground='red')
        self.tree.tag_configure('high', foreground='orange')
        
    def finish_ui_scan(self, count):
        self.status_text.config(text=f"AUDIT COMPLETE: {count} FILES SEALED", fg="#27ae60")
        self.status_icon.config(text="✅")

if __name__ == "__main__":
    init_db() # Ensure DB is ready
    root = tk.Tk()
    app = USBSentryGUI(root)
    root.mainloop()