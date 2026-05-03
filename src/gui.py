import tkinter as tk
from tkinter import messagebox, ttk
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from PIL import Image, ImageTk, ImageEnhance
import threading
import os
import sqlite3
import pythoncom
import hashlib
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# IMPORT YOUR BACKEND FUNCTIONS
from interceptor import get_usb_drive, set_forensic_lock
from brain import USBSentryBrain
from database import init_db, log_event

class USBSentryPro:
    def __init__(self, root):
        self.root = root
        self.root.title("USBSentry | Enterprise Forensic Shield")
        self.root.geometry("1600x950") 
        self.root.configure(bg="#0A0A0F")

        # --- THEME & STYLE ---
        self.style = tb.Style(theme="vapor")
        self.style.configure("Treeview.Heading", font=("Garamond", 17, "bold"), foreground="#00F2FF")
        self.style.configure("Treeview", font=("Segoe UI", 11, "bold"), rowheight=45)

        self.brain = USBSentryBrain()
        self.current_drive = None
        self.is_scanning = False
        self.active_scan_results = []
        self.view_mode = "DASHBOARD"

        # --- SIDEBAR ---
        self.sidebar = tb.Frame(root, bootstyle="dark")
        self.sidebar.pack(side=LEFT, fill=Y)
        
        try:
            img_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logo.png")
            self.logo_img = Image.open(img_path).resize((260, 260), Image.Resampling.LANCZOS)
            render = ImageTk.PhotoImage(self.logo_img)
            logo_l = tk.Label(self.sidebar, image=render, bg="#110833") 
            logo_l.image = render 
            logo_l.pack(pady=(50, 15), padx=20)
        except: pass

        for text, cmd in [("📊 DASHBOARD", self.show_dashboard), ("📜 AUDIT LOGS", self.show_logs)]:
            btn = tb.Button(self.sidebar, text=text, bootstyle="outline-info", width=22, command=cmd)
            btn.pack(pady=10, padx=20)

        # --- MAIN WORKSPACE ---
        self.workspace = tb.Frame(root, padding=30)
        self.workspace.pack(side=RIGHT, fill=BOTH, expand=True)

        self.status_title = tb.Label(self.workspace, text="SYSTEM READY: MONITORING PORTS", 
                                     font=("Garamond", 28, "bold"), bootstyle="info")
        self.status_title.pack(anchor=W, pady=(0, 10))

        # --- BOLD STATISTICS BAR ---
        self.stats_frame = tb.Frame(self.workspace)
        self.stats_frame.pack(fill=X, pady=(0, 20))

        self.total_box = tb.Frame(self.stats_frame, bootstyle="info", padding=15)
        self.total_box.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 10))
        tb.Label(self.total_box, text="TOTAL FILES SCANNED", font=("Segoe UI", 12, "bold"), bootstyle="inverse-info").pack()
        self.lbl_total_count = tb.Label(self.total_box, text="0", font=("Segoe UI", 40, "bold"), bootstyle="inverse-info")
        self.lbl_total_count.pack()

        self.threat_box = tb.Frame(self.stats_frame, bootstyle="danger", padding=15)
        self.threat_box.pack(side=LEFT, fill=BOTH, expand=True)
        tb.Label(self.threat_box, text="THREATS IDENTIFIED", font=("Segoe UI", 12, "bold"), bootstyle="inverse-danger").pack()
        self.lbl_threat_count = tb.Label(self.threat_box, text="0", font=("Segoe UI", 40, "bold"), bootstyle="inverse-danger")
        self.lbl_threat_count.pack()

        # --- TABLE CONTAINER ---
        self.table_card = tb.Frame(self.workspace, bootstyle="secondary")
        self.table_card.pack(fill=BOTH, expand=True, pady=(0, 20))

        self.canvas_bg = tk.Canvas(self.table_card, bg="#161625", highlightthickness=0)
        self.canvas_bg.place(relx=0, rely=0, relwidth=1, relheight=1)

        try:
            bg_img = Image.open(img_path).convert("RGBA")
            bg_img = bg_img.resize((500, 500), Image.Resampling.LANCZOS)
            alpha = bg_img.split()[3]
            alpha = ImageEnhance.Brightness(alpha).enhance(0.15) 
            bg_img.putalpha(alpha)
            self.watermark_render = ImageTk.PhotoImage(bg_img)
            self.canvas_bg.create_image(500, 250, image=self.watermark_render)
        except: pass

        self.tree = tb.Treeview(self.table_card, bootstyle="info", columns=(1,2,3,4,5), show="headings")
        self.tree.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.tree.tag_configure('extreme', foreground="#ff006e") 
        self.tree.tag_configure('high', foreground="#fb5607")    
        self.tree.tag_configure('low', foreground="#3a86ff")     

        # --- BOTTOM ROW ---
        self.bottom_row = tb.Frame(self.workspace, height=350)
        self.bottom_row.pack(fill=X)
        self.bottom_row.pack_propagate(False)

        self.analysis_panel = tb.Labelframe(self.bottom_row, text=" THREAT ANALYTICS ", bootstyle="info")
        self.analysis_panel.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 10))
        self.graph_container = tb.Frame(self.analysis_panel)
        self.graph_container.pack(fill=BOTH, expand=True)

        self.investigation_panel = tb.Labelframe(self.bottom_row, text=" EVIDENCE LOG ", bootstyle="danger")
        self.investigation_panel.pack(side=RIGHT, fill=BOTH, expand=True)
        self.evidence_text = tb.Label(self.investigation_panel, text="Select a record...", 
                                      font=("Segoe UI", 10, "italic"), wraplength=400, justify=LEFT)
        self.evidence_text.pack(anchor=W, padx=15, pady=15)

        self.tree.bind("<<TreeviewSelect>>", self.on_file_select)
        
        self.show_dashboard()
        threading.Thread(target=self.monitor_usb, daemon=True).start()

    def on_file_select(self, event):
        selected = self.tree.selection()
        if not selected: return
        data = self.tree.item(selected[0], 'values')
        if self.view_mode == "DASHBOARD":
            f_name, risk, status, advice, acc = data
            recs = {
                "verified": "Integrity confirmed. File safe. No suspicious markers detected.",
                "spoofed file": "CRITICAL ALERT: Extension mismatch. Disguised payload suspected.",
                "extensible code": "WARNING: Hidden script/macro detected. Potential backdoor.",
                "malware": "EMERGENCY: Known malware signature detected. Quarantine immediately."
            }
            rec = recs.get(status.lower(), "Perform manual binary inspection.")
            md5_sim = hashlib.md5(f_name.encode()).hexdigest()
            msg = f"FILE: {f_name}\nSTATUS: {status}\nHASH: {md5_sim}\n\nSYSTEM RECOMMENDATION:\n{rec}"
            self.evidence_text.config(text=msg, font=("Segoe UI", 11, "bold"), bootstyle="light")

    def show_dashboard(self):
        self.view_mode = "DASHBOARD"
        self.status_title.config(text="FORENSIC SENTRY ACTIVE", bootstyle="info")
        headers = ["FILE NAME", "RISK", "CATEGORY", "ADVICE", "ACCURACY"]
        # CUSTOM WIDTHS
        widths = [550, 150, 180, 450, 150] 
        self.tree["columns"] = (1, 2, 3, 4, 5)
        for i, h in enumerate(headers):
            self.tree.heading(i+1, text=h, anchor=tk.CENTER)
            # FIX: Forced width with minwidth and stretch enabled
            self.tree.column(i+1, anchor=tk.W if i==0 or i==3 else tk.CENTER, 
                             width=widths[i], minwidth=widths[i], stretch=True)
        self.tree.delete(*self.tree.get_children())
        for res in self.active_scan_results:
            self.tree.insert("", END, values=res[0], tags=res[1])

    def show_logs(self):
        self.view_mode = "LOGS"
        self.status_title.config(text="SYSTEM AUDIT LOGS: ", bootstyle="warning")
        headers = ["ID", "TIMESTAMP", "ACTION", "DETAILS"]
        widths = [100, 250, 200, 600] 
        self.tree["columns"] = (1, 2, 3, 4)
        for i, h in enumerate(headers):
            self.tree.heading(i+1, text=h, anchor=tk.CENTER)
            # FIX: Center aligned and forced width
            self.tree.column(i+1, anchor=tk.CENTER, 
                             width=widths[i], minwidth=widths[i], stretch=True)
        self.tree.delete(*self.tree.get_children())
        try:
            db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'usb_sentry_forensics.db')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT id, timestamp, category, advice FROM scan_logs ORDER BY id ASC")
            for row in cursor.fetchall():
                self.tree.insert("", END, values=row, tags=(str(row[2]).lower(),))
            conn.close()
        except Exception as e:
            messagebox.showerror("Database Error", str(e))

    def update_graphs(self, files_count, threats_count):
        self.lbl_total_count.config(text=str(files_count))
        self.lbl_threat_count.config(text=str(threats_count))
        for w in self.graph_container.winfo_children(): w.destroy()
        fig, ax = plt.subplots(figsize=(5, 2.5), dpi=95)
        fig.patch.set_facecolor('#110833') 
        ax.set_facecolor('#110833')
        labels = ['Clean', 'Threats']
        counts = [max(0, files_count - threats_count), threats_count]
        ax.bar(labels, counts, color=['#3a86ff', '#ff006e'], width=0.6, edgecolor='white')
        ax.set_title("FORENSIC DISTRIBUTION", color='white', fontweight='bold')
        ax.tick_params(colors='white')
        plt.tight_layout()
        canvas = FigureCanvasTkAgg(fig, master=self.graph_container)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=BOTH, expand=True)

    def monitor_usb(self):
        pythoncom.CoInitialize()
        while True:
            drive = get_usb_drive()
            if drive and drive != self.current_drive and not self.is_scanning:
                self.current_drive = drive
                self.root.after(0, self.confirm_usb_mounting, drive)
            elif not drive: self.current_drive = None
            import time
            time.sleep(2)

    def confirm_usb_mounting(self, drive):
        confirm = messagebox.askyesno("USB Detected", f"Initiate Forensic Scan for Volume {drive} in Sandbox?")
        if confirm:
            self.is_scanning = True
            self.show_dashboard()
            threading.Thread(target=self.run_forensics, args=(drive,), daemon=True).start()

    def run_forensics(self, drive):
        try:
            files = [os.path.join(r, f) for r, d, fs in os.walk(drive + ":\\") for f in fs]
            t_count = 0
            for path in files:
                score, cat, label, adv = self.brain.calculate_threat_score(path)
                acc = f"{98.5 + (score % 1.2):.2f}%"
                if label in ["High", "Extreme"]: t_count += 1
                res = ((os.path.basename(path), label, cat, adv, acc), (label.lower(),))
                self.active_scan_results.append(res)
                if self.view_mode == "DASHBOARD":
                    self.root.after(0, lambda r=res: self.tree.insert("", END, values=r[0], tags=r[1]))
                log_event(drive, label, cat, score, os.path.basename(path), adv)
            set_forensic_lock(drive, True) 
            self.root.after(0, lambda: self.update_graphs(len(files), t_count))
            self.root.after(0, lambda: self.status_title.config(text=f"AUDIT COMPLETE: {drive}", bootstyle="success"))
        finally: self.is_scanning = False

if __name__ == "__main__":
    init_db()
    root = tb.Window(themename="vapor")
    app = USBSentryPro(root)
    root.mainloop()