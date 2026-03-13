import customtkinter as ctk
from tkinter import filedialog, messagebox
import tkinter as tk
import threading
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from settings import load_config, save_config
from detector import parse_input
from analyzer import analyze_batch
from html_export import export_html
from pdf_export import export_pdf

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

RISK_COLORS = {"Critical": "#ff4757", "High": "#ff6b35", "Medium": "#ffa502",
               "Low": "#7bed9f", "Clean": "#2ed573", "Unknown": "#8b949e"}
RISK_ICONS  = {"Critical": "🔴", "High": "🟠", "Medium": "🟡",
               "Low": "🟢", "Clean": "✅", "Unknown": "⚪"}


class IOCHunterApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("IOCHunter — Threat Intelligence Analyzer")
        self.geometry("1100x760")
        self.minsize(900, 600)
        self.config = load_config()
        self.analyzed_results = []
        self._build_menu()
        self._build_ui()

    def _build_menu(self):
        menubar = tk.Menu(self, bg="#161b22", fg="#c9d1d9",
                          activebackground="#21d4fd", activeforeground="#000000",
                          relief="flat", borderwidth=0)
        file_menu = tk.Menu(menubar, tearoff=0, bg="#161b22", fg="#c9d1d9",
                            activebackground="#21d4fd", activeforeground="#000000")
        file_menu.add_command(label="📂  Open File...", command=self._open_file)
        file_menu.add_separator()
        file_menu.add_command(label="📄  Export PDF", command=self._export_pdf)
        file_menu.add_command(label="🌐  Export HTML", command=self._export_html)
        file_menu.add_separator()
        file_menu.add_command(label="🚪  Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        view_menu = tk.Menu(menubar, tearoff=0, bg="#161b22", fg="#c9d1d9",
                            activebackground="#21d4fd", activeforeground="#000000")
        view_menu.add_command(label="🗑  Clear Results", command=self._clear_all)
        menubar.add_cascade(label="View", menu=view_menu)

        settings_menu = tk.Menu(menubar, tearoff=0, bg="#161b22", fg="#c9d1d9",
                                 activebackground="#21d4fd", activeforeground="#000000")
        settings_menu.add_command(label="🔑  API Keys", command=self._open_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        help_menu = tk.Menu(menubar, tearoff=0, bg="#161b22", fg="#c9d1d9",
                             activebackground="#21d4fd", activeforeground="#000000")
        help_menu.add_command(label="📖  IOC Reference Guide", command=self._open_help)
        help_menu.add_command(label="ℹ️   About IOCHunter", command=self._open_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.configure(menu=menubar)

    def _build_ui(self):
        top = ctk.CTkFrame(self, fg_color="#161b22", corner_radius=0, height=60)
        top.pack(fill="x", side="top")
        top.pack_propagate(False)
        ctk.CTkLabel(top, text="🔍 IOCHunter",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color="#21d4fd").pack(side="left", padx=20, pady=10)
        ctk.CTkLabel(top, text="Threat Intelligence Analyzer",
                     font=ctk.CTkFont(size=12),
                     text_color="#8b949e").pack(side="left", padx=0, pady=10)
        self.ai_var = ctk.BooleanVar(value=self.config.get("ai_enabled", False))
        ctk.CTkSwitch(top, text="🤖 AI Mode", variable=self.ai_var,
                      font=ctk.CTkFont(size=11), progress_color="#21d4fd",
                      command=self._toggle_ai).pack(side="right", padx=20)

        main = ctk.CTkFrame(self, fg_color="#0d1117", corner_radius=0)
        main.pack(fill="both", expand=True)

        left = ctk.CTkFrame(main, fg_color="#0d1117", corner_radius=0, width=340)
        left.pack(side="left", fill="y", padx=(12, 6), pady=12)
        left.pack_propagate(False)
        ctk.CTkLabel(left, text="INPUT", font=ctk.CTkFont(size=10, weight="bold"),
                     text_color="#8b949e").pack(anchor="w", padx=4, pady=(0, 4))
        self.input_box = ctk.CTkTextbox(left, font=ctk.CTkFont(family="Courier", size=12),
                                         fg_color="#161b22", border_color="#30363d",
                                         border_width=1, corner_radius=8, text_color="#c9d1d9")
        self.input_box.pack(fill="both", expand=True)
        self.input_box.insert("0.0", "Paste IOCs here, one per line...\n\n"
                                      "Examples:\n8.8.8.8\nevil.com\n"
                                      "d41d8cd98f00b204e9800998ecf8427e\nCVE-2024-1234")

        btn_row = ctk.CTkFrame(left, fg_color="transparent")
        btn_row.pack(fill="x", pady=(8, 0))
        ctk.CTkButton(btn_row, text="📂 Open File", width=110, height=36,
                       fg_color="#1c2333", hover_color="#21262d",
                       border_color="#30363d", border_width=1,
                       font=ctk.CTkFont(size=12),
                       command=self._open_file).pack(side="left", padx=(0, 6))
        ctk.CTkButton(btn_row, text="🗑 Clear", width=80, height=36,
                       fg_color="#1c2333", hover_color="#21262d",
                       border_color="#30363d", border_width=1,
                       font=ctk.CTkFont(size=12),
                       command=self._clear_input).pack(side="left")

        self.analyze_btn = ctk.CTkButton(left, text="🔍  ANALYZE", height=44,
                                          corner_radius=8, fg_color="#21d4fd",
                                          hover_color="#17a8c9", text_color="#000000",
                                          font=ctk.CTkFont(size=14, weight="bold"),
                                          command=self._start_analysis)
        self.analyze_btn.pack(fill="x", pady=(10, 0))
        self.progress_label = ctk.CTkLabel(left, text="", font=ctk.CTkFont(size=10),
                                            text_color="#8b949e")
        self.progress_label.pack(anchor="w", pady=(6, 0))
        self.progress_bar = ctk.CTkProgressBar(left, fg_color="#1c2333",
                                                progress_color="#21d4fd", height=4)
        self.progress_bar.pack(fill="x", pady=(4, 0))
        self.progress_bar.set(0)

        right = ctk.CTkFrame(main, fg_color="#0d1117", corner_radius=0)
        right.pack(side="left", fill="both", expand=True, padx=(6, 12), pady=12)
        results_header = ctk.CTkFrame(right, fg_color="transparent")
        results_header.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(results_header, text="RESULTS",
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color="#8b949e").pack(side="left", padx=4)
        export_row = ctk.CTkFrame(results_header, fg_color="transparent")
        export_row.pack(side="right")
        ctk.CTkButton(export_row, text="📄 PDF", width=80, height=28,
                       fg_color="#1c2333", hover_color="#21262d",
                       border_color="#30363d", border_width=1,
                       font=ctk.CTkFont(size=11),
                       command=self._export_pdf).pack(side="left", padx=(0, 6))
        ctk.CTkButton(export_row, text="🌐 HTML", width=80, height=28,
                       fg_color="#1c2333", hover_color="#21262d",
                       border_color="#30363d", border_width=1,
                       font=ctk.CTkFont(size=11),
                       command=self._export_html).pack(side="left")
        self.results_frame = ctk.CTkScrollableFrame(right, fg_color="#0d1117", corner_radius=0)
        self.results_frame.pack(fill="both", expand=True)
        self._show_empty_state()

    def _start_analysis(self):
        raw = self.input_box.get("0.0", "end").strip()
        if not raw or raw.startswith("Paste IOCs"):
            messagebox.showwarning("No Input", "Please enter at least one IOC to analyze.")
            return
        iocs = parse_input(raw)
        if not iocs:
            messagebox.showwarning("No IOCs Detected",
                                   "Could not detect any valid IOCs.\n\n"
                                   "Go to Help → IOC Reference Guide for supported formats.")
            return
        self.analyze_btn.configure(state="disabled", text="⏳  Analyzing...")
        self.progress_bar.set(0)
        self.progress_label.configure(text=f"Detected {len(iocs)} IOCs...")
        self._clear_results()

        def run():
            def on_progress(done, total):
                self.after(0, lambda: self.progress_bar.set(done / total))
                self.after(0, lambda: self.progress_label.configure(text=f"Analyzing {done}/{total}..."))
            results = analyze_batch(iocs, progress_callback=on_progress)
            self.analyzed_results = results
            self.after(0, lambda: self._display_results(results))
            self.after(0, lambda: self.analyze_btn.configure(state="normal", text="🔍  ANALYZE"))
            self.after(0, lambda: self.progress_label.configure(text=f"✅ Done — {len(results)} IOCs analyzed"))
        threading.Thread(target=run, daemon=True).start()

    def _display_results(self, results):
        self._clear_results()
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Clean": 0, "Unknown": 0}
        for r in results:
            risk = r.get("overall_risk", "Unknown")
            counts[risk] = counts.get(risk, 0) + 1

        summary = ctk.CTkFrame(self.results_frame, fg_color="#161b22",
                                corner_radius=8, border_color="#30363d", border_width=1)
        summary.pack(fill="x", pady=(0, 10), padx=2)
        for label, key, color in [("Total", None, "#21d4fd"), ("Critical", "Critical", "#ff4757"),
                                   ("High", "High", "#ff6b35"), ("Medium", "Medium", "#ffa502"),
                                   ("Clean", "Clean", "#2ed573")]:
            val = len(results) if key is None else counts.get(key, 0)
            col = ctk.CTkFrame(summary, fg_color="transparent")
            col.pack(side="left", padx=20, pady=10)
            ctk.CTkLabel(col, text=str(val), font=ctk.CTkFont(size=22, weight="bold"),
                          text_color=color).pack()
            ctk.CTkLabel(col, text=label, font=ctk.CTkFont(size=9), text_color="#8b949e").pack()
        for ioc in results:
            self._build_ioc_card(ioc)

    def _build_ioc_card(self, ioc):
        risk = ioc.get("overall_risk", "Unknown")
        risk_color = RISK_COLORS.get(risk, "#8b949e")
        risk_icon = RISK_ICONS.get(risk, "⚪")
        card = ctk.CTkFrame(self.results_frame, fg_color="#161b22",
                             corner_radius=8, border_color="#30363d", border_width=1)
        card.pack(fill="x", pady=(0, 8), padx=2)
        header = ctk.CTkFrame(card, fg_color="#1c2333", corner_radius=0)
        header.pack(fill="x")
        ctk.CTkLabel(header, text=f"{risk_icon}  {ioc['value']}",
                     font=ctk.CTkFont(family="Courier", size=13, weight="bold"),
                     text_color="#e6edf3").pack(side="left", padx=14, pady=10)
        ctk.CTkLabel(header, text=f" {ioc['type']} ",
                     font=ctk.CTkFont(size=9, weight="bold"),
                     fg_color="#1f3a5f", text_color="#79c0ff",
                     corner_radius=4).pack(side="left", padx=4)
        ctk.CTkLabel(header, text=f" {risk} ",
                     font=ctk.CTkFont(size=9, weight="bold"),
                     fg_color="#0d1117", text_color=risk_color,
                     corner_radius=4).pack(side="left", padx=4)

        api_grid = ctk.CTkFrame(card, fg_color="transparent")
        api_grid.pack(fill="x", padx=10, pady=8)
        col_idx = 0
        for api_name, res in ioc["results"].items():
            if res.get("skipped"):
                continue
            block = ctk.CTkFrame(api_grid, fg_color="#0d1117",
                                  corner_radius=6, border_color="#21262d", border_width=1)
            block.grid(row=0, column=col_idx, padx=5, pady=4, sticky="nsew")
            api_grid.columnconfigure(col_idx, weight=1)
            col_idx += 1
            ctk.CTkLabel(block, text=res.get("source", api_name).upper(),
                          font=ctk.CTkFont(size=9, weight="bold"),
                          text_color="#58a6ff").pack(anchor="w", padx=10, pady=(8, 4))
            ctk.CTkFrame(block, fg_color="#21262d", height=1, corner_radius=0).pack(fill="x", padx=8)
            if res.get("error"):
                ctk.CTkLabel(block, text=f"⚠ {res['error']}",
                              font=ctk.CTkFont(size=9), text_color="#f85149",
                              wraplength=160).pack(anchor="w", padx=10, pady=6)
            elif not res.get("found"):
                ctk.CTkLabel(block, text="Not found",
                              font=ctk.CTkFont(size=9),
                              text_color="#8b949e").pack(anchor="w", padx=10, pady=6)
            else:
                for label, value in [
                    ("Score", res.get("score")),
                    ("Abuse Score", f"{res.get('abuse_score')}%" if res.get("abuse_score") is not None else None),
                    ("Reports", res.get("total_reports")),
                    ("OTX Pulses", res.get("pulse_count")),
                    ("Country", res.get("country")),
                    ("ISP", res.get("isp", "")[:22] if res.get("isp") else None),
                    ("Org", res.get("org", "")[:22] if res.get("org") else None),
                    ("TOR", "⚠ Yes" if res.get("is_tor") else None),
                    ("Risk", res.get("risk")),
                ]:
                    if value is not None and value != "" and value != 0:
                        row_f = ctk.CTkFrame(block, fg_color="transparent")
                        row_f.pack(fill="x", padx=10, pady=1)
                        ctk.CTkLabel(row_f, text=label, font=ctk.CTkFont(size=8),
                                      text_color="#8b949e", width=70, anchor="w").pack(side="left")
                        val_color = RISK_COLORS.get(str(value), "#e6edf3") if label == "Risk" else "#e6edf3"
                        ctk.CTkLabel(row_f, text=str(value), font=ctk.CTkFont(size=8, weight="bold"),
                                      text_color=val_color, anchor="w").pack(side="left")
            ctk.CTkFrame(block, fg_color="transparent", height=6).pack()

    def _show_empty_state(self):
        frame = ctk.CTkFrame(self.results_frame, fg_color="transparent")
        frame.pack(expand=True, fill="both")
        ctk.CTkLabel(frame, text="🔍", font=ctk.CTkFont(size=48)).pack(pady=(60, 10))
        ctk.CTkLabel(frame, text="Paste IOCs on the left and click Analyze",
                     font=ctk.CTkFont(size=14), text_color="#8b949e").pack()
        ctk.CTkLabel(frame, text="Supports: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, Email, CVE",
                     font=ctk.CTkFont(size=11), text_color="#484f58").pack(pady=(8, 0))

    def _clear_results(self):
        for w in self.results_frame.winfo_children():
            w.destroy()

    def _clear_all(self):
        self._clear_input()
        self._clear_results()
        self.analyzed_results = []
        self.progress_bar.set(0)
        self.progress_label.configure(text="")
        self._show_empty_state()

    def _clear_input(self):
        self.input_box.delete("0.0", "end")

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="Open IOC file",
            filetypes=[("Text files", "*.txt *.csv *.log"), ("All files", "*.*")])
        if path:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                self.input_box.delete("0.0", "end")
                self.input_box.insert("0.0", content)
            except Exception as e:
                messagebox.showerror("Error", f"Could not open file:\n{e}")

    def _export_html(self):
        if not self.analyzed_results:
            messagebox.showwarning("No Results", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".html",
            filetypes=[("HTML files", "*.html")], initialfile="iochunter_report.html")
        if path:
            if export_html(self.analyzed_results, path):
                messagebox.showinfo("Exported", f"HTML report saved to:\n{path}")
            else:
                messagebox.showerror("Error", "Failed to export HTML report.")

    def _export_pdf(self):
        if not self.analyzed_results:
            messagebox.showwarning("No Results", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")], initialfile="iochunter_report.pdf")
        if path:
            if export_pdf(self.analyzed_results, path):
                messagebox.showinfo("Exported", f"PDF report saved to:\n{path}")
            else:
                messagebox.showerror("Error", "Failed to export PDF report.")

    def _toggle_ai(self):
        self.config["ai_enabled"] = self.ai_var.get()
        save_config(self.config)

    def _open_settings(self):
        SettingsWindow(self)

    def _open_help(self):
        HelpWindow(self)

    def _open_about(self):
        AboutWindow(self)


# Este archivo reemplaza la clase SettingsWindow en main_app.py
# Copia y pega esta clase completa reemplazando la que existe en main_app.py

import customtkinter as ctk
from tkinter import messagebox
import threading
import requests

def _test_virustotal(key):
    try:
        r = requests.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                         headers={"x-apikey": key}, timeout=15)
        if r.status_code == 200:
            return True, "✅ Connected"
        elif r.status_code == 401:
            return False, "❌ Invalid key"
        else:
            return False, f"❌ HTTP {r.status_code}"
    except requests.exceptions.Timeout:
        return False, "⚠ Timeout"
    except Exception as e:
        return False, f"❌ {str(e)[:40]}"

def _test_abuseipdb(key):
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": key, "Accept": "application/json"},
                         params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90},
                         timeout=15)
        if r.status_code == 200:
            return True, "✅ Connected"
        elif r.status_code == 401:
            return False, "❌ Invalid key"
        else:
            return False, f"❌ HTTP {r.status_code}"
    except requests.exceptions.Timeout:
        return False, "⚠ Timeout"
    except Exception as e:
        return False, f"❌ {str(e)[:40]}"

def _test_alienvault(key):
    try:
        r = requests.get("https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general",
                         headers={"X-OTX-API-KEY": key}, timeout=30)
        if r.status_code == 200:
            return True, "✅ Connected"
        elif r.status_code == 401:
            return False, "❌ Invalid key"
        else:
            return False, f"❌ HTTP {r.status_code}"
    except requests.exceptions.Timeout:
        return False, "⚠ Timeout (OTX slow)"
    except Exception as e:
        return False, f"❌ {str(e)[:40]}"

def _test_ipinfo(key):
    try:
        params = {"token": key} if key else {}
        r = requests.get("https://ipinfo.io/8.8.8.8/json", params=params, timeout=15)
        if r.status_code == 200:
            return True, "✅ Connected"
        elif r.status_code == 401:
            return False, "❌ Invalid key"
        else:
            return False, f"❌ HTTP {r.status_code}"
    except requests.exceptions.Timeout:
        return False, "⚠ Timeout"
    except Exception as e:
        return False, f"❌ {str(e)[:40]}"

def _test_greynoise(key):
    try:
        r = requests.get("https://api.greynoise.io/v3/community/8.8.8.8",
                         headers={"key": key}, timeout=15)
        if r.status_code in (200, 404):
            return True, "✅ Connected"
        elif r.status_code == 401:
            return False, "❌ Invalid key"
        else:
            return False, f"❌ HTTP {r.status_code}"
    except requests.exceptions.Timeout:
        return False, "⚠ Timeout"
    except Exception as e:
        return False, f"❌ {str(e)[:40]}"

def _test_urlscan(key):
    try:
        r = requests.get("https://urlscan.io/user/quotas/",
                         headers={"API-Key": key}, timeout=15)
        if r.status_code == 200:
            return True, "✅ Connected"
        elif r.status_code == 401:
            return False, "❌ Invalid key"
        else:
            return False, f"❌ HTTP {r.status_code}"
    except requests.exceptions.Timeout:
        return False, "⚠ Timeout"
    except Exception as e:
        return False, f"❌ {str(e)[:40]}"

def _test_shodan(key):
    try:
        r = requests.get(f"https://api.shodan.io/api-info?key={key}", timeout=15)
        if r.status_code == 200:
            return True, "✅ Connected"
        elif r.status_code == 401:
            return False, "❌ Invalid key"
        else:
            return False, f"❌ HTTP {r.status_code}"
    except requests.exceptions.Timeout:
        return False, "⚠ Timeout"
    except Exception as e:
        return False, f"❌ {str(e)[:40]}"

def _test_generic(key):
    if not key.strip():
        return False, "⚪ No key set"
    return True, "✅ Key saved"

API_TESTERS = {
    "virustotal":     _test_virustotal,
    "abuseipdb":      _test_abuseipdb,
    "alienvault":     _test_alienvault,
    "ipinfo":         _test_ipinfo,
    "greynoise":      _test_greynoise,
    "urlscan":        _test_urlscan,
    "shodan":         _test_shodan,
    "malwarebazaar":  _test_generic,
    "threatfox":      _test_generic,
    "hybrid_analysis":_test_generic,
}


class SettingsWindow(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Settings — API Keys")
        self.geometry("560x680")
        self.resizable(False, False)
        self.grab_set()

        try:
            from settings import load_config, save_config
        except ImportError:
            from config.settings import load_config, save_config
        self._load_config = load_config
        self._save_config = save_config
        self.config_data = load_config()
        self._build()

    def _build(self):
        ctk.CTkLabel(self, text="🔑  API Keys Configuration",
                     font=ctk.CTkFont(size=16, weight="bold"),
                     text_color="#21d4fd").pack(padx=24, pady=(20, 4), anchor="w")
        ctk.CTkLabel(self, text="Keys are stored locally on your machine and never shared.",
                     font=ctk.CTkFont(size=11), text_color="#8b949e").pack(padx=24, anchor="w")

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=16, pady=12)

        apis = [
            ("VirusTotal",      "virustotal",      "https://virustotal.com"),
            ("AbuseIPDB",       "abuseipdb",       "https://abuseipdb.com"),
            ("AlienVault OTX",  "alienvault",      "https://otx.alienvault.com"),
            ("IPinfo",          "ipinfo",          "https://ipinfo.io"),
            ("GreyNoise",       "greynoise",       "https://greynoise.io"),
            ("MalwareBazaar",   "malwarebazaar",   "https://bazaar.abuse.ch"),
            ("URLScan.io",      "urlscan",         "https://urlscan.io"),
            ("ThreatFox",       "threatfox",       "https://threatfox.abuse.ch"),
            ("Shodan",          "shodan",          "https://shodan.io"),
            ("Hybrid Analysis", "hybrid_analysis", "https://hybrid-analysis.com"),
        ]

        self.entries = {}
        self.status_labels = {}

        for label, key, url in apis:
            frame = ctk.CTkFrame(scroll, fg_color="#161b22", corner_radius=8,
                                  border_color="#30363d", border_width=1)
            frame.pack(fill="x", pady=4)

            # Header row
            header = ctk.CTkFrame(frame, fg_color="transparent")
            header.pack(fill="x", padx=12, pady=(10, 2))
            ctk.CTkLabel(header, text=label,
                          font=ctk.CTkFont(size=12, weight="bold"),
                          text_color="#e6edf3").pack(side="left")
            ctk.CTkLabel(header, text=url,
                          font=ctk.CTkFont(size=9),
                          text_color="#58a6ff").pack(side="left", padx=10)

            # Input row — key field + test button + status
            input_row = ctk.CTkFrame(frame, fg_color="transparent")
            input_row.pack(fill="x", padx=12, pady=(4, 10))

            entry = ctk.CTkEntry(input_row, placeholder_text="Enter API key...",
                                  show="•", height=34,
                                  fg_color="#0d1117", border_color="#30363d",
                                  font=ctk.CTkFont(family="Courier", size=11))
            entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

            current = self.config_data.get("api_keys", {}).get(key, "")
            if current:
                entry.insert(0, current)
            self.entries[key] = entry

            # Status label
            status_lbl = ctk.CTkLabel(input_row, text="",
                                       font=ctk.CTkFont(size=10),
                                       text_color="#8b949e", width=140, anchor="w")
            status_lbl.pack(side="right", padx=(0, 8))
            self.status_labels[key] = status_lbl

            # Test button
            test_btn = ctk.CTkButton(input_row, text="Test",
                                      width=60, height=34,
                                      fg_color="#1c2333", hover_color="#21262d",
                                      border_color="#30363d", border_width=1,
                                      font=ctk.CTkFont(size=11),
                                      command=lambda k=key, e=entry, s=status_lbl: self._test_single(k, e, s))
            test_btn.pack(side="right", padx=(0, 4))

        # Bottom buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=16, pady=(0, 16))

        ctk.CTkButton(btn_frame, text="🔌 Test All", width=120, height=36,
                       fg_color="#1c2333", hover_color="#21262d",
                       border_color="#30363d", border_width=1,
                       command=self._test_all).pack(side="left", padx=(0, 8))

        ctk.CTkButton(btn_frame, text="💾 Save", width=100, height=36,
                       fg_color="#21d4fd", hover_color="#17a8c9",
                       text_color="#000000", font=ctk.CTkFont(weight="bold"),
                       command=self._save).pack(side="right")

    def _test_single(self, key, entry, status_lbl):
        api_key = entry.get().strip()
        if not api_key:
            try:
                status_lbl.configure(text="⚪ No key entered", text_color="#8b949e")
            except Exception:
                pass
            return

        try:
            status_lbl.configure(text="⏳ Testing...", text_color="#ffa502")
        except Exception:
            return

        def run():
            tester = API_TESTERS.get(key, _test_generic)
            success, msg = tester(api_key)
            color = "#2ed573" if success else "#ff4757" if "❌" in msg else "#ffa502"
            def safe_update():
                try:
                    status_lbl.configure(text=msg, text_color=color)
                except Exception:
                    pass  # Widget was destroyed, ignore
            self.after(0, safe_update)

        threading.Thread(target=run, daemon=True).start()

    def _test_all(self):
        for key, entry in self.entries.items():
            status_lbl = self.status_labels[key]
            self._test_single(key, entry, status_lbl)

    def _save(self):
        for key, entry in self.entries.items():
            self.config_data["api_keys"][key] = entry.get()
        if self._save_config(self.config_data):
            messagebox.showinfo("Saved", "API keys saved successfully.", parent=self)
            self.destroy()
        else:
            messagebox.showerror("Error", "Failed to save configuration.", parent=self)

class HelpWindow(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("IOC Reference Guide")
        self.geometry("600x560")
        self.resizable(False, True)
        self.grab_set()
        self._build()

    def _build(self):
        ctk.CTkLabel(self, text="📖  IOC Reference Guide",
                     font=ctk.CTkFont(size=16, weight="bold"),
                     text_color="#21d4fd").pack(padx=24, pady=(20, 4), anchor="w")
        ctk.CTkLabel(self, text="Supported indicator types and how to use them",
                     font=ctk.CTkFont(size=11), text_color="#8b949e").pack(padx=24, anchor="w")
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=16, pady=12)
        for name, ioc_type, example, apis in [
            ("IPv4 Address", "IPv4", "45.33.32.156", "VirusTotal, AbuseIPDB, AlienVault, IPinfo"),
            ("IPv6 Address", "IPv6", "2001:db8::1", "VirusTotal, AbuseIPDB, AlienVault, IPinfo"),
            ("Domain", "Domain", "evil-domain.com", "VirusTotal, AlienVault"),
            ("URL", "URL", "http://evil.com/payload.exe", "VirusTotal, AlienVault"),
            ("MD5 Hash", "MD5", "d41d8cd98f00b204e9800998ecf8427e", "VirusTotal, AlienVault"),
            ("SHA1 Hash", "SHA1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", "VirusTotal, AlienVault"),
            ("SHA256 Hash", "SHA256", "64 hex characters", "VirusTotal, AlienVault"),
            ("Email", "Email", "attacker@evil.com", "AbuseIPDB"),
            ("CVE", "CVE", "CVE-2024-1234", "AlienVault"),
        ]:
            card = ctk.CTkFrame(scroll, fg_color="#161b22", corner_radius=8,
                                 border_color="#30363d", border_width=1)
            card.pack(fill="x", pady=4)
            top_row = ctk.CTkFrame(card, fg_color="transparent")
            top_row.pack(fill="x", padx=12, pady=(10, 2))
            ctk.CTkLabel(top_row, text=name, font=ctk.CTkFont(size=12, weight="bold"),
                          text_color="#e6edf3").pack(side="left")
            ctk.CTkLabel(top_row, text=f" {ioc_type} ",
                          font=ctk.CTkFont(size=9, weight="bold"),
                          fg_color="#1f3a5f", text_color="#79c0ff",
                          corner_radius=4).pack(side="left", padx=8)
            ctk.CTkLabel(card, text=f"Example: {example}",
                          font=ctk.CTkFont(family="Courier", size=10),
                          text_color="#8b949e").pack(anchor="w", padx=12, pady=(0, 2))
            ctk.CTkLabel(card, text=f"APIs: {apis}",
                          font=ctk.CTkFont(size=10), text_color="#484f58").pack(
                anchor="w", padx=12, pady=(0, 10))


class AboutWindow(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("About IOCHunter")
        self.geometry("400x340")
        self.resizable(False, False)
        self.grab_set()
        self._build()

    def _build(self):
        ctk.CTkLabel(self, text="🔍", font=ctk.CTkFont(size=52)).pack(pady=(30, 8))
        ctk.CTkLabel(self, text="IOCHunter",
                     font=ctk.CTkFont(size=22, weight="bold"),
                     text_color="#21d4fd").pack()
        ctk.CTkLabel(self, text="Threat Intelligence Analyzer",
                     font=ctk.CTkFont(size=12), text_color="#8b949e").pack(pady=(2, 0))
        ctk.CTkLabel(self, text="Version 1.0.0  —  Phase 1",
                     font=ctk.CTkFont(size=10), text_color="#484f58").pack(pady=(4, 20))
        ctk.CTkFrame(self, fg_color="#30363d", height=1, corner_radius=0).pack(fill="x", padx=30)
        for label, value in [
            ("APIs", "VirusTotal · AbuseIPDB · AlienVault · IPinfo"),
            ("Platform", "Windows · Linux · macOS"),
            ("Language", "Python 3.10+"),
            ("License", "MIT — Open Source"),
            ("GitHub", "github.com/yourusername/IOCHunter"),
        ]:
            row = ctk.CTkFrame(self, fg_color="transparent")
            row.pack(pady=3)
            ctk.CTkLabel(row, text=f"{label}:", font=ctk.CTkFont(size=11),
                          text_color="#8b949e", width=80, anchor="e").pack(side="left", padx=(0, 8))
            ctk.CTkLabel(row, text=value, font=ctk.CTkFont(size=11),
                          text_color="#e6edf3").pack(side="left")
