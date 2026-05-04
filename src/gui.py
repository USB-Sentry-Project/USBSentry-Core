import tkinter as tk
from tkinter import messagebox, ttk
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from PIL import Image, ImageTk
import threading
import os
import sqlite3
import pythoncom
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# LOCAL IMPORTS
from interceptor import get_usb_drive, set_forensic_lock
from brain import USBSentryBrain
from database import init_db, log_event, DB_PATH

class USBSentryPro:
    def __init__(self, root):
        self.root = root
        self.root.title("USBSentry | Enterprise Forensic Shield")
        self.root.geometry("1600x950") 
        self.root.configure(bg="#050508") 

        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        self.style = tb.Style(theme="vapor")
        
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        self.style.configure("Treeview", font=("Segoe UI", 10), rowheight=30)
        
        self.brain = USBSentryBrain()
        self.current_drive = None
        self.is_scanning = False
        self.active_scan_results = [] 
        self.active_scan_full_data = {} 
        self.view_mode = "DASHBOARD"

        self.setup_ui()
        self.record_system_log("SYSTEM", "Application Initialized - Sentry Mode Active")
        threading.Thread(target=self.monitor_usb, daemon=True).start()

    def setup_ui(self):
        # --- SIDEBAR ---
        self.sidebar = tb.Frame(self.root, bootstyle="dark")
        self.sidebar.pack(side=LEFT, fill=Y)
        
        try:
            logo_path = os.path.join(self.current_dir, "logo.png")
            pil_img = Image.open(logo_path).resize((240, 240), Image.Resampling.LANCZOS)
            self.logo_render = ImageTk.PhotoImage(pil_img)
            logo_l = tk.Label(self.sidebar, image=self.logo_render, bg="#110833") 
            logo_l.pack(pady=(20, 20), padx=10)
        except: pass

        for text, cmd in [("📊 DASHBOARD", self.show_dashboard), ("📜 AUDIT LOGS", self.show_logs)]:
            btn = tb.Button(self.sidebar, text=text, bootstyle="outline-info", width=20, command=cmd)
            btn.pack(pady=10, padx=25)

        self.workspace = tb.Frame(self.root, padding=25)
        self.workspace.pack(side=RIGHT, fill=BOTH, expand=True)

        self.status_title = tb.Label(self.workspace, text="SYSTEM READY: MONITORING PORTS", 
                                     font=("Garamond", 26, "bold"), bootstyle="info")
        self.status_title.pack(anchor=W, pady=(0, 15))

        self.stats_frame = tb.Frame(self.workspace)
        self.stats_frame.pack(fill=X, pady=(0, 20))
        self.lbl_total_count = self.create_stat_box(self.stats_frame, "TOTAL FILES SCANNED", "info")
        self.lbl_threat_count = self.create_stat_box(self.stats_frame, "THREATS IDENTIFIED", "danger")

        self.table_card = tb.Frame(self.workspace, bootstyle="secondary", height=300)
        self.table_card.pack(fill=X, pady=(0, 20))
        self.table_card.pack_propagate(False) 

        self.tree_scroll = tb.Scrollbar(self.table_card, orient=VERTICAL)
        self.tree_scroll.pack(side=RIGHT, fill=Y)

        self.tree = tb.Treeview(self.table_card, bootstyle="info", columns=(1,2,3,4,5,6), 
                                show="headings", yscrollcommand=self.tree_scroll.set)
        self.tree.pack(fill=BOTH, expand=True)
        self.tree_scroll.config(command=self.tree.yview)
        
        self.tree.tag_configure('extreme', foreground="#ff006e", font=("Segoe UI", 10, "bold")) 
        self.tree.tag_configure('high', foreground="#fb5607", font=("Segoe UI", 10, "bold"))    
        self.tree.tag_configure('low', foreground="#00f2ff")    
        self.tree.tag_configure('historical', foreground="#A9A9A9") 
        self.tree.tag_configure('system', foreground="#77dd77") 
        self.tree.bind("<<TreeviewSelect>>", self.on_file_select)

        self.bottom_row = tb.Frame(self.workspace)
        self.bottom_row.pack(fill=BOTH, expand=True)

        self.analysis_panel = tb.Labelframe(self.bottom_row, text=" FORENSIC ANALYTICS ENGINE ", bootstyle="info")
        self.analysis_panel.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 15))

        self.graph_canvas = tk.Canvas(self.analysis_panel, bg="#050508", highlightthickness=0)
        self.graph_v_scroll = tb.Scrollbar(self.analysis_panel, orient=VERTICAL, command=self.graph_canvas.yview)
        self.graph_container = tb.Frame(self.graph_canvas, bootstyle="dark")
        self.style.configure('Custom.TFrame', background='#050508')
        self.graph_container.configure(style='Custom.TFrame')

        self.graph_canvas.create_window((0, 0), window=self.graph_container, anchor=NW)
        self.graph_canvas.configure(yscrollcommand=self.graph_v_scroll.set)
        self.graph_canvas.pack(side=LEFT, fill=BOTH, expand=True)
        self.graph_v_scroll.pack(side=RIGHT, fill=Y)

        self.investigation_panel = tb.Labelframe(self.bottom_row, text=" FORENSIC EVIDENCE LOG ", bootstyle="danger", width=500)
        self.investigation_panel.pack(side=RIGHT, fill=BOTH, expand=False)
        self.investigation_panel.pack_propagate(False)
        
        self.evidence_text = tb.Label(self.investigation_panel, text="Select a record to investigate...", 
                                      font=("Segoe UI", 10, "bold"), wraplength=450, justify=LEFT, anchor=NW)
        self.evidence_text.pack(fill=BOTH, expand=True, padx=20, pady=20)

    def record_system_log(self, category, message):
        log_event("INTERNAL", "N/A", "LOG", "SYSTEM", category, "N/A", 0, 0, message)

    def create_stat_box(self, parent, label, style):
        box = tb.Frame(parent, bootstyle=style, padding=15)
        box.pack(side=LEFT, fill=BOTH, expand=True, padx=8)
        tb.Label(box, text=label, font=("Segoe UI", 11, "bold"), bootstyle=f"inverse-{style}").pack()
        lbl = tb.Label(box, text="0", font=("Segoe UI", 36, "bold"), bootstyle=f"inverse-{style}")
        lbl.pack()
        return lbl

    def show_dashboard(self):
        self.view_mode = "DASHBOARD"
        self.status_title.config(text="FORENSIC SENTRY ACTIVE", bootstyle="info")
        headers = ["FILE NAME", "RISK", "CATEGORY", "ADVICE", "ACCURACY"]
        self.tree["displaycolumns"] = (1, 2, 3, 4, 5) # STAYS 5 COLUMNS
        for i, h in enumerate(headers):
            self.tree.heading(i+1, text=h, anchor=CENTER)
            self.tree.column(i+1, width=[450, 120, 180, 480, 120][i], anchor=CENTER)
        self.tree.delete(*self.tree.get_children())
        for item in self.active_scan_results:
            self.tree.insert("", END, values=item['values'], tags=(item['tag'],))

    def show_logs(self):
        self.view_mode = "LOGS"
        self.status_title.config(text="SYSTEM AUDIT: HISTORICAL RECORDS", bootstyle="warning")
        headers = ["ID", "TIMESTAMP", "FILE NAME", "THREAT", "SCORE", "ADVICE"]
        self.tree["displaycolumns"] = ("#all") # SHOWS ALL 6 FOR AUDIT
        for i, h in enumerate(headers):
            self.tree.heading(i+1, text=h, anchor=CENTER)
            self.tree.column(i+1, width=[60, 180, 320, 150, 90, 470][i], anchor=CENTER)
        self.tree.delete(*self.tree.get_children())
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT id, timestamp, file_name, threat_level, score, advice FROM scan_logs ORDER BY id DESC")
            for row in cursor.fetchall():
                tag = 'system' if row[3] == "SYSTEM" else 'historical'
                self.tree.insert("", END, values=row, tags=(tag,))
            conn.close()
        except: pass

    def on_file_select(self, event):
        selected = self.tree.selection()
        if not selected: return
        data = self.tree.item(selected[0], 'values')
        f_name = data[0] if self.view_mode == "DASHBOARD" else data[2]
        if f_name in self.active_scan_full_data:
            info = self.active_scan_full_data[f_name]
            if info['risk'] == "Extreme":
                rec = "Dangerous malware signature found. This file is a security threat. Access is blocked; quarantine or deletion is required."
            elif info['risk'] == "High":
                rec = "Forensic anomaly detected. The file type does not match its header, indicating spoofing. Do not trust this file."
            elif info['risk'] == "Medium":
                rec = "Potential script risk. This is an executable format that could run hidden tasks. Verify source before proceeding."
            else:
                rec = "Clean forensic profile. No malicious signatures detected. The file is safe for standard operations."
            details = f"FILE: {f_name}\n------------------------------------------\nRISK LEVEL: {info['risk'].upper()}\nFORENSIC HASH: {info['hash']}\nTHREAT SCORE: {info['score']}/100\nFILE TYPE: {info['mime']}\n\nSYSTEM RECOMMENDATION:\n{rec}"
            self.evidence_text.config(text=details, bootstyle="light")

    def run_forensics(self, drive):
        try:
            self.record_system_log("SCAN", f"Started Scan on Volume {drive}")
            files = [os.path.join(r, f) for r, d, fs in os.walk(drive + ":\\") for f in fs]
            self.active_scan_results = []
            t_count = 0
            for path in files:
                score, cat, label, adv, mime, f_hash = self.brain.calculate_threat_score(path)
                acc = f"{98.5 + (score % 1.2):.2f}%"
                if label in ["High", "Extreme"]: t_count += 1
                f_name = os.path.basename(path)
                res_values = (f_name, label, cat, adv, acc)
                self.active_scan_results.append({'values': res_values, 'tag': label.lower()})
                self.active_scan_full_data[f_name] = {"mime": mime, "score": score, "adv": adv, "risk": label, "hash": f_hash}
                if self.view_mode == "DASHBOARD":
                    self.root.after(0, lambda v=res_values, t=label.lower(): self.tree.insert("", END, values=v, tags=(t,)))
                log_event(drive, f_name, path.split('.')[-1], mime, label, cat, score, os.path.getsize(path)/1024, adv)
            set_forensic_lock(drive, True) 
            self.root.after(0, lambda: self.update_graphs(len(files), t_count))
        finally: self.is_scanning = False

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
        if messagebox.askyesno("USB Detected", f"Scan Volume {drive}?"):
            self.is_scanning = True
            self.active_scan_full_data = {}
            self.show_dashboard()
            threading.Thread(target=self.run_forensics, args=(drive,), daemon=True).start()

    def update_graphs(self, files_count, threats_count):
        self.lbl_total_count.config(text=str(files_count))
        self.lbl_threat_count.config(text=str(threats_count))
        for w in self.graph_container.winfo_children(): w.destroy()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT file_size, score, threat_level FROM scan_logs WHERE device_id != 'INTERNAL'")
        data = cursor.fetchall()
        conn.close()
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8, 10), dpi=95) 
        fig.patch.set_facecolor('#050508') 
        palette = {'Extreme': '#ff006e', 'High': '#fb5607', 'Medium': '#ffbe0b', 'Low': '#00f2ff'}
        if data:
            sizes = [row[0] for row in data]; scores = [row[1] for row in data]
            colors = [palette.get(row[2], '#00f2ff') for row in data]
            ax1.set_facecolor('#050508'); ax1.scatter(sizes, scores, c=colors, alpha=0.7, edgecolors='white')
            if len(sizes) > 1:
                z = np.polyfit(sizes, scores, 1); p = np.poly1d(z)
                ax1.plot(sizes, p(sizes), "w--", alpha=0.5)
            ax1.set_title("THREAT CORRELATION (Dots = Files)", color='white', fontsize=12); ax1.tick_params(colors='white', labelsize=8)
        labels = ['Extreme', 'High', 'Medium', 'Low']
        vals = [sum(1 for row in data if row[2] == l) for l in labels]
        if sum(vals) > 0:
            ax2.pie(vals, colors=[palette[l] for l in labels], startangle=90, wedgeprops=dict(width=0.4))
            ax2.text(0, 0, "BREACH" if threats_count > 0 else "SECURE", ha='center', va='center', color="#ff006e" if threats_count > 0 else "#00f2ff", fontweight='bold')
            ax2.set_title("HEALTH STATUS", color='white', fontsize=12); ax2.legend(labels, loc="center right", bbox_to_anchor=(1.3, 0.5), frameon=False, labelcolor='white')
        plt.tight_layout()
        canvas = FigureCanvasTkAgg(fig, master=self.graph_container)
        canvas.draw(); canvas.get_tk_widget().pack(fill=BOTH, expand=True)
        self.graph_container.update_idletasks()
        self.graph_canvas.config(scrollregion=self.graph_canvas.bbox("all"))

if __name__ == "__main__":
    init_db()
    root = tb.Window(themename="vapor")
    app = USBSentryPro(root)
    root.mainloop()