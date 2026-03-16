import tkinter as tk
from tkinter import scrolledtext, ttk
import threading
from datetime import datetime
import nmap
import queue

from nvd_client import fetch_cves
from scorer import score_service, score_overall
from reporter import save_html_report


def detect_gateway() -> str:
    """Auto-detect the default gateway IP at runtime."""
    try:
        import subprocess
        result = subprocess.check_output(
            ["ip", "route"], text=True
        )
        for line in result.splitlines():
            if line.startswith("default"):
                parts = line.split()
                idx = parts.index("via")
                return parts[idx + 1]
    except Exception:
        pass
    return ""

# ── palette ───────────────────────────────────────────────────────
BG           = "#080808"
BG_PANEL     = "#0e0e0e"
BG_INPUT     = "#141414"
BG_HOVER     = "#1a1a1a"
FG           = "#dedede"
FG_DIM       = "#3a3a3a"
FG_MID       = "#666666"
FG_LABEL     = "#999999"
RED          = "#c0392b"
RED_LIT      = "#e74c3c"
ORANGE       = "#c0621a"
ORANGE_LIT   = "#e67e22"
YELLOW       = "#b7950b"
YELLOW_LIT   = "#f1c40f"
GREEN        = "#1e8449"
GREEN_LIT    = "#2ecc71"
CYAN         = "#1a5276"
CYAN_LIT     = "#3498db"
WHITE        = "#f5f5f5"
ACCENT       = "#c0392b"

FONT         = ("Courier New", 10)
FONT_B       = ("Courier New", 10, "bold")
FONT_SM      = ("Courier New", 8)
FONT_SM_B    = ("Courier New", 8, "bold")
FONT_LG      = ("Courier New", 13, "bold")
FONT_XL      = ("Courier New", 18, "bold")

SEV_COLOR = {
    "CRITICAL": RED_LIT,
    "HIGH":     ORANGE_LIT,
    "MEDIUM":   YELLOW_LIT,
    "LOW":      GREEN_LIT,
    "NONE":     FG_MID,
    "UNKNOWN":  FG_MID,
}

MAX_HISTORY = 5
SEGMENTS    = 24   # number of blocks in pulse bar


class ScanRecord:
    """Holds everything about one completed scan."""
    def __init__(self, target, timestamp):
        self.target    = target
        self.timestamp = timestamp
        self.log_lines = []   # list of (text, tag)
        self.enriched  = []
        self.overall   = {}
        self.label     = f"{target}  [{timestamp}]"


class PortMortemApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PortMortem")
        self.root.configure(bg=BG)
        self.root.minsize(980, 740)
        self.root.resizable(True, True)

        self._stop_flag      = False
        self._enriched       = []
        self._total_svcs     = 0
        self._done_svcs      = 0
        self._scanning       = False
        self._history        = []          # list of ScanRecord
        self._active_record  = None

        # pulse bar state
        self._seg_states     = [0.0] * SEGMENTS
        self._seg_phase      = 0
        self._pulse_job      = None
        self._ui_queue = queue.Queue()
        self._seg_canvas     = None
        self._seg_rects      = []

        self._build_ui()
        self._process_ui_queue()
        self._pulse_tick()

    # ═══════════════════════════════════════════════════════════════
    # UI BUILD
    # ═══════════════════════════════════════════════════════════════
    def _process_ui_queue(self):
        """Drain the UI queue on the main thread — called every 50ms."""
        try:
            while True:
                fn, args = self._ui_queue.get_nowait()
                fn(*args)
        except queue.Empty:
            pass
        self.root.after(50, self._process_ui_queue)

    def _ui(self, fn, *args):
        """Queue a UI update to be run on the main thread."""
        self._ui_queue.put((fn, args))

    def _build_ui(self):
        self._build_header()
        self._build_controls()
        self._build_pulse_bar()
        self._build_body()
        self._build_footer()

    # ── header ────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self.root, bg=BG)
        hdr.pack(fill="x")

        tk.Frame(hdr, bg=ACCENT, height=2).pack(fill="x")

        inner = tk.Frame(hdr, bg=BG)
        inner.pack(fill="x", padx=20, pady=12)

        left = tk.Frame(inner, bg=BG)
        left.pack(side="left")

        tk.Label(left, text="PORTMORTEM",
                 bg=BG, fg=ACCENT, font=FONT_XL).pack(anchor="w")
        tk.Label(left, text="network vulnerability scanner  //  nvd cve risk scoring",
                 bg=BG, fg=FG_MID, font=FONT_SM).pack(anchor="w")

        # live clock top-right
        self._clock_var = tk.StringVar()
        tk.Label(inner, textvariable=self._clock_var,
                 bg=BG, fg=FG_DIM, font=FONT_SM).pack(side="right", anchor="ne")
        self._tick_clock()

        tk.Frame(hdr, bg=FG_DIM, height=1).pack(fill="x")

    # ── controls ──────────────────────────────────────────────────
    def _build_controls(self):
        bar = tk.Frame(self.root, bg=BG_PANEL)
        bar.pack(fill="x", padx=0)
        tk.Frame(bar, bg=BG_PANEL).pack(fill="x", padx=20, pady=10)

        row = tk.Frame(bar, bg=BG_PANEL)
        row.pack(fill="x", padx=20, pady=(0, 10))

        # target
        self._lbl(row, "TARGET").pack(side="left")
        self.target_var = tk.StringVar(value=detect_gateway())
        self._inp(row, self.target_var, 22).pack(side="left", padx=(5, 20))

        # ports
        self._lbl(row, "START PORT").pack(side="left")
        self.start_port = tk.StringVar(value="1")
        self._inp(row, self.start_port, 7).pack(side="left", padx=(5, 14))

        self._lbl(row, "END PORT").pack(side="left")
        self.end_port = tk.StringVar(value="1024")
        self._inp(row, self.end_port, 7).pack(side="left", padx=(5, 14))

        self.full_scan = tk.BooleanVar(value=False)
        tk.Checkbutton(
            row, text="1–65535",
            variable=self.full_scan,
            bg=BG_PANEL, fg=FG_MID,
            selectcolor=BG_INPUT,
            activebackground=BG_PANEL,
            activeforeground=FG,
            font=FONT_SM,
            command=self._toggle_full,
        ).pack(side="left", padx=(0, 20))

        # buttons
        self.btn_start  = self._btn(row, "▶ SCAN",    GREEN_LIT, "#000", self._start)
        self.btn_stop   = self._btn(row, "■ STOP",    RED_LIT,   "#000", self._stop,   dis=True)
        self.btn_clear  = self._btn(row, "✕ CLEAR",   BG_HOVER,  FG_MID, self._clear)
        self.btn_export = self._btn(row, "⬇ EXPORT",  CYAN_LIT,  "#000", self._export, dis=True)

        for b in (self.btn_start, self.btn_stop,
                  self.btn_clear, self.btn_export):
            b.pack(side="left", padx=3)

        tk.Frame(bar, bg=FG_DIM, height=1).pack(fill="x")

    # ── pulse bar ─────────────────────────────────────────────────
    def _build_pulse_bar(self):
        wrap = tk.Frame(self.root, bg=BG, pady=6)
        wrap.pack(fill="x", padx=20)

        top = tk.Frame(wrap, bg=BG)
        top.pack(fill="x")

        self.status_var = tk.StringVar(value="IDLE")
        tk.Label(top, textvariable=self.status_var,
                 bg=BG, fg=FG_MID, font=FONT_SM_B,
                 width=14, anchor="w").pack(side="left")

        self.pct_var = tk.StringVar(value="")
        tk.Label(top, textvariable=self.pct_var,
                 bg=BG, fg=FG_MID, font=FONT_SM,
                 anchor="e").pack(side="right")

        self._seg_canvas = tk.Canvas(
            wrap, bg=BG, height=18,
            highlightthickness=0, bd=0
        )
        self._seg_canvas.pack(fill="x", pady=(4, 0))
        self._seg_canvas.bind("<Configure>", self._draw_segments)
        self._seg_progress = 0.0   # 0.0 – 1.0, how far scan is
        self._seg_lit_color = ACCENT

    # ── body: log + results side by side ──────────────────────────
    def _build_body(self):
        body = tk.PanedWindow(
            self.root, orient="horizontal",
            bg=FG_DIM, sashwidth=3, sashrelief="flat"
        )
        body.pack(fill="both", expand=True, padx=20, pady=8)

        # left: log panel
        left = tk.Frame(body, bg=BG)
        self._build_log_panel(left)
        body.add(left, minsize=340)

        # right: results panel
        right = tk.Frame(body, bg=BG)
        self._build_results_panel(right)
        body.add(right, minsize=320)

    def _build_log_panel(self, parent):
        self._section_label(parent, "SCAN LOG")

        # history dropdown row
        hist_row = tk.Frame(parent, bg=BG)
        hist_row.pack(fill="x", pady=(0, 4))

        self._lbl(hist_row, "HISTORY").pack(side="left")

        self.history_var = tk.StringVar(value="— current scan —")
        self.history_menu = ttk.Combobox(
            hist_row,
            textvariable=self.history_var,
            state="readonly",
            font=FONT_SM,
            width=36,
        )
        self._style_combobox()
        self.history_menu.pack(side="left", padx=(6, 8))
        self.history_menu.bind("<<ComboboxSelected>>", self._load_history)

        self.btn_hist_export = self._btn(
            hist_row, "⬇ EXPORT", CYAN_LIT, "#000",
            self._export_history, dis=True
        )
        self.btn_hist_export.pack(side="left")

        # log text
        self.log = scrolledtext.ScrolledText(
            parent,
            bg=BG_PANEL, fg=FG,
            font=FONT,
            relief="flat", bd=0,
            insertbackground=FG,
            selectbackground=BG_HOVER,
            state="disabled",
            wrap="word",
        )
        self.log.pack(fill="both", expand=True)

        for tag, color in {
            "good": GREEN_LIT, "bad": RED_LIT,
            "warn": YELLOW_LIT, "info": CYAN_LIT,
            "dim":  FG_DIM,    "mid":  FG_MID,
            "white": WHITE,
        }.items():
            self.log.tag_config(tag, foreground=color)
        self.log.tag_config("bold", font=FONT_B)

    def _build_results_panel(self, parent):
        self._section_label(parent, "RESULTS")

        cols    = ("port","proto","service","product",
                   "version","cves","score","severity")
        headers = ("PORT","PROTO","SERVICE","PRODUCT",
                   "VERSION","CVEs","SCORE","SEV")
        widths  = (50, 46, 80, 100, 80, 46, 56, 78)

        s = ttk.Style()
        s.theme_use("default")
        s.configure("PM.Treeview",
            background=BG_PANEL, fieldbackground=BG_PANEL,
            foreground=FG, font=FONT, rowheight=21, borderwidth=0)
        s.configure("PM.Treeview.Heading",
            background=BG_INPUT, foreground=FG_MID,
            font=FONT_SM_B, relief="flat")
        s.map("PM.Treeview",
            background=[("selected", BG_HOVER)],
            foreground=[("selected", WHITE)])

        vsb = tk.Scrollbar(parent, orient="vertical",   bg=BG_INPUT)
        hsb = tk.Scrollbar(parent, orient="horizontal",  bg=BG_INPUT)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")

        self.tree = ttk.Treeview(
            parent, columns=cols, show="tree headings",
            style="PM.Treeview",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
        )
        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        self.tree.column("#0", width=22, minwidth=22, stretch=False)
        for col, hdr, w in zip(cols, headers, widths):
            self.tree.heading(col, text=hdr)
            self.tree.column(col, width=w, minwidth=w, anchor="center")

        for sev, fg in SEV_COLOR.items():
            self.tree.tag_configure(sev, foreground=fg)
        self.tree.tag_configure("CVE_HEAD",
            foreground=FG_MID, font=FONT_SM_B)
        self.tree.tag_configure("CVE_ROW",
            foreground=FG_MID, font=FONT_SM)

        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Button-1>", self._on_tree_click)
        tk.Label(parent,
            text="click a CVE-ID to open in browser",
            bg=BG, fg=FG_DIM, font=FONT_SM
        ).pack(anchor="w", pady=(2, 0))

        # risk summary strip at bottom of results
        self.risk_strip = tk.Frame(parent, bg=BG_INPUT)
        self.risk_strip.pack(fill="x", pady=(4, 0))
        self.risk_var = tk.StringVar(value="no scan results")
        tk.Label(self.risk_strip, textvariable=self.risk_var,
                 bg=BG_INPUT, fg=FG_MID,
                 font=FONT_SM_B, anchor="center",
                 pady=5).pack(fill="x")

    # ── footer ────────────────────────────────────────────────────
    def _build_footer(self):
        tk.Frame(self.root, bg=FG_DIM, height=1).pack(fill="x", padx=20)
        foot = tk.Frame(self.root, bg=BG)
        foot.pack(fill="x", padx=20, pady=(3, 8))
        self.footer_var = tk.StringVar(value="portmortem  //  ready")
        tk.Label(foot, textvariable=self.footer_var,
                 bg=BG, fg=FG_DIM, font=FONT_SM, anchor="w").pack(side="left")
        import random
        _QUOTES = [
            "the quieter you become, the more you can hear.",
            "there is no patch for human stupidity.",
            "security is a process, not a product.",
            "every port is a door. some are left open.",
            "know your network before someone else does.",
            "assumption is the mother of all misconfigurations.",
            "nmap sees what you forgot was running.",
        ]
        tk.Label(foot,
            text=random.choice(_QUOTES),
            bg=BG, fg=FG_DIM, font=FONT_SM, anchor="e"
        ).pack(side="right")

    # ═══════════════════════════════════════════════════════════════
    # WIDGET HELPERS
    # ═══════════════════════════════════════════════════════════════

    def _lbl(self, parent, text):
        return tk.Label(parent, text=text,
                        bg=parent.cget("bg"),
                        fg=FG_LABEL, font=FONT_SM)

    def _inp(self, parent, var, w):
        return tk.Entry(parent,
                        textvariable=var,
                        bg=BG_INPUT, fg=WHITE,
                        insertbackground=WHITE,
                        font=FONT, width=w,
                        relief="flat", bd=5,
                        highlightthickness=1,
                        highlightbackground=FG_DIM,
                        highlightcolor=ACCENT)

    def _btn(self, parent, text, bg, fg, cmd, dis=False):
        return tk.Button(
            parent, text=text,
            bg=bg, fg=fg,
            activebackground=bg, activeforeground=fg,
            font=FONT_SM_B,
            relief="flat", bd=0,
            padx=12, pady=5,
            cursor="hand2",
            command=cmd,
            state="disabled" if dis else "normal",
        )

    def _section_label(self, parent, text):
        row = tk.Frame(parent, bg=BG)
        row.pack(fill="x", pady=(0, 4))
        tk.Label(row, text=f"── {text} ",
                 bg=BG, fg=FG_DIM,
                 font=FONT_SM_B, anchor="w").pack(side="left")
        tk.Frame(row, bg=FG_DIM, height=1).pack(
            side="left", fill="x", expand=True, pady=5)

    def _style_combobox(self):
        s = ttk.Style()
        s.configure("TCombobox",
            fieldbackground=BG_INPUT,
            background=BG_INPUT,
            foreground=FG,
            selectbackground=BG_HOVER,
            selectforeground=WHITE,
            arrowcolor=FG_MID,
        )

    # ═══════════════════════════════════════════════════════════════
    # PULSE BAR
    # ═══════════════════════════════════════════════════════════════

    def _draw_segments(self, event=None):
        c = self._seg_canvas
        c.delete("all")
        W = c.winfo_width()
        H = 18
        if W < 10:
            return

        gap   = 3
        total = SEGMENTS * gap + (SEGMENTS - 1) * 2
        seg_w = max(4, (W - (SEGMENTS - 1) * gap) // SEGMENTS)

        self._seg_rects = []
        for i in range(SEGMENTS):
            x0 = i * (seg_w + gap)
            x1 = x0 + seg_w
            brightness = self._seg_states[i]
            color = self._seg_color(brightness)
            rid = c.create_rectangle(x0, 2, x1, H - 2,
                                     fill=color, outline="")
            self._seg_rects.append((rid, x0, x1, seg_w))

    def _seg_color(self, brightness):
        """Interpolate from BG_INPUT to lit color based on brightness 0–1."""
        def parse(h):
            h = h.lstrip("#")
            return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

        def blend(a, b, t):
            return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))

        def to_hex(rgb):
            return "#{:02x}{:02x}{:02x}".format(*rgb)

        base = parse(BG_INPUT)
        lit  = parse(self._seg_lit_color)
        return to_hex(blend(base, lit, brightness))

    def _pulse_tick(self):
        if self._scanning:
            # wave animation — segments light up in a travelling wave
            for i in range(SEGMENTS):
                # how many segments should be lit based on progress
                lit_count = int(self._seg_progress * SEGMENTS)
                if i < lit_count:
                    # lit segments: add a ripple on top
                    wave = 0.6 + 0.4 * abs(
                        __import__("math").sin(
                            (self._seg_phase - i) * 0.4
                        )
                    )
                    self._seg_states[i] = wave
                else:
                    # unlit: faint ambient glow
                    self._seg_states[i] = max(
                        0.0,
                        self._seg_states[i] - 0.08
                    )
            self._seg_phase += 1
        else:
            # idle: slow breathe on first few segments
            import math
            breath = 0.08 + 0.07 * math.sin(self._seg_phase * 0.05)
            for i in range(SEGMENTS):
                self._seg_states[i] = breath * max(0, 1 - i * 0.15)
            self._seg_phase += 1

        self._draw_segments()
        self._pulse_job = self.root.after(60, self._pulse_tick)

    def _set_progress(self, pct, color=None):
        self._seg_progress = max(0.0, min(1.0, pct))
        if color:
            self._seg_lit_color = color
        if pct >= 1.0:
            self.pct_var.set("100%")
        elif pct <= 0.0:
            self.pct_var.set("")
        else:
            self.pct_var.set(f"{int(pct * 100)}%")

    # ═══════════════════════════════════════════════════════════════
    # LOG
    # ═══════════════════════════════════════════════════════════════

    def _log(self, msg, tag="", record=None):
        ts = datetime.now().strftime("%H:%M:%S")
        line_ts   = f"[{ts}]  "
        line_msg  = msg + "\n"

        self.log.configure(state="normal")
        self.log.insert("end", line_ts,  "dim")
        self.log.insert("end", line_msg, tag)
        self.log.configure(state="disabled")
        self.log.see("end")

        if record is not None:
            record.log_lines.append((line_ts, "dim"))
            record.log_lines.append((line_msg, tag))

    def _log_div(self, record=None):
        self._log("─" * 48, "dim", record)

    def _clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ═══════════════════════════════════════════════════════════════
    # HISTORY
    # ═══════════════════════════════════════════════════════════════

    def _save_to_history(self, record: ScanRecord):
        self._history.insert(0, record)
        if len(self._history) > MAX_HISTORY:
            self._history = self._history[:MAX_HISTORY]

        labels = [r.label for r in self._history]
        self.history_menu["values"] = labels
        self.history_var.set(labels[0])
        self.btn_hist_export.configure(state="normal")

    def _load_history(self, event=None):
        label = self.history_var.get()
        record = next((r for r in self._history if r.label == label), None)
        if not record:
            return

        # repopulate log
        self._clear_log()
        self.log.configure(state="normal")
        for text, tag in record.log_lines:
            self.log.insert("end", text, tag)
        self.log.configure(state="disabled")
        self.log.see("end")

        # repopulate tree
        for row in self.tree.get_children():
            self.tree.delete(row)
        for enriched in record.enriched:
            self._add_tree_row(enriched)

        # update risk strip
        if record.overall:
            self._update_risk_strip(record.overall)

        self.footer_var.set(
            f"viewing history  //  {record.target}  //  {record.timestamp}"
        )

    def _export_history(self):
        label = self.history_var.get()
        record = next((r for r in self._history if r.label == label), None)
        if not record or not record.enriched:
            return
        path = save_html_report(
            record.enriched, record.target, record.overall)
        self._log(f"Exported → {path}", "info")

    # ═══════════════════════════════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════════════════════════════

    def _toggle_full(self):
        if self.full_scan.get():
            self.start_port.set("1")
            self.end_port.set("65535")

    def _on_tree_click(self, event):
        """Open CVE link in browser when a CVE ID cell is clicked."""
        import webbrowser
        item = self.tree.identify_row(event.y)
        col  = self.tree.identify_column(event.x)
        if not item or col != "#3":   # column 3 = service/cve id
            return
        vals = self.tree.item(item, "values")
        if vals and str(vals[2]).startswith("CVE-"):
            url = f"https://nvd.nist.gov/vuln/detail/{vals[2]}"
            webbrowser.open(url)

    def _clear(self):
        self._clear_log()
        for row in self.tree.get_children():
            self.tree.delete(row)
        self._enriched = []
        self._set_progress(0.0, ACCENT)
        self.status_var.set("IDLE")
        self.pct_var.set("")
        self.risk_var.set("no scan results")
        self.footer_var.set("portmortem  //  ready")
        self.btn_export.configure(state="disabled")

    def _export(self):
        if not self._enriched:
            return
        overall = score_overall([e["risk"] for e in self._enriched])
        path = save_html_report(
            self._enriched, self.target_var.get(), overall)
        self._log(f"Report saved → {path}", "info")

    def _stop(self):
        self._stop_flag = True
        self._log("Stop requested...", "warn")
        self.status_var.set("STOPPING")

    def _start(self):
        self._stop_flag  = False
        self._enriched   = []
        self._total_svcs = 0
        self._done_svcs  = 0
        self._scanning   = True
        self._clear()

        self._seg_lit_color = ACCENT
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_export.configure(state="disabled")
        self.status_var.set("SCANNING")
        self._set_progress(0.05)

        threading.Thread(target=self._run, daemon=True).start()

    # ═══════════════════════════════════════════════════════════════
    # SCAN THREAD
    # ═══════════════════════════════════════════════════════════════

    def _run(self):
        target = self.target_var.get().strip()
        p1     = self.start_port.get().strip()
        p2     = self.end_port.get().strip()
        ts     = datetime.now().strftime("%Y-%m-%d %H:%M")
        record = ScanRecord(target, ts)

        if not target:
            self._log("No target specified.", "bad", record)
            self._finish(record)
            return

        self._log(f"Target   {target}", "white", record)
        self._log(f"Ports    {p1} – {p2}", "white", record)
        self._log_div(record)
        self._ui(self._set_progress, 0.1, ACCENT)

        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=target,
                    arguments=f"-sV -T4 --open -p {p1}-{p2}")
        except Exception as e:
            self._log(f"Nmap error: {e}", "bad", record)
            self._finish(record)
            return

        services = []
        for host in nm.all_hosts():
            self._log(f"Host up  →  {host}", "good", record)
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto]):
                    s = nm[host][proto][port]
                    svc = {
                        "host": host, "port": port,
                        "protocol": proto, "state": s["state"],
                        "service":  s["name"],
                        "product":  s.get("product", ""),
                        "version":  s.get("version", ""),
                    }
                    services.append(svc)
                    self._log(
                        f"  [+] {port}/{proto:<4}  "
                        f"{s['name']:<12}  "
                        f"{s.get('product','')} "
                        f"{s.get('version','')}",
                        "good", record
                    )

        self._ui(self._set_progress, 0.25, ACCENT)

        if not services:
            self._log("No open ports found.", "warn", record)
            self._ui(self._set_progress, 1.0, FG_MID)
            self._finish(record)
            return

        self._total_svcs = len(services)
        self._log_div(record)
        self._log(f"Found {len(services)} port(s)  →  fetching CVEs", "info", record)
        self._log_div(record)

        for i, svc in enumerate(services):
            if self._stop_flag:
                break

            product = svc["product"] or svc["service"]
            self._ui(self.status_var.set, f"CVE  {product}")
            self._log(f"Lookup  {product} {svc['version']}", "mid", record)

            cves = fetch_cves(product, svc["version"])
            risk = score_service(cves)
            enriched = {**svc, "cves": cves, "risk": risk}
            self._enriched.append(enriched)
            record.enriched.append(enriched)

            sev = risk["severity"]
            tag = {"CRITICAL":"bad","HIGH":"warn",
                "MEDIUM":"warn","LOW":"good"}.get(sev, "mid")

            self._log(
                f"  {svc['port']}  {risk['cve_count']} CVEs  "
                f"score {risk['score']}  [{sev}]",
                tag, record
            )

            # progress goes from 25% to 95% across CVE lookups
            pct = 0.25 + 0.70 * ((i + 1) / self._total_svcs)
            col = {"CRITICAL": RED_LIT, "HIGH": ORANGE_LIT,
                "MEDIUM":   YELLOW_LIT, "LOW": GREEN_LIT}.get(sev, ACCENT)
            self._ui(self._set_progress, pct, col)
            self._ui(self._add_tree_row, enriched)

        self._log_div(record)

        if self._enriched:
            overall = score_overall([e["risk"] for e in self._enriched])
            record.overall = overall
            sev = overall["severity"]
            tag = {"CRITICAL":"bad","HIGH":"warn",
                "MEDIUM":"warn","LOW":"good"}.get(sev, "mid")
            col = {"CRITICAL": RED_LIT, "HIGH": ORANGE_LIT,
                "MEDIUM":   YELLOW_LIT, "LOW": GREEN_LIT}.get(sev, GREEN_LIT)

            self._log(
                f"Risk score  {overall['score']} / 10  —  {sev}",
                tag, record
            )
            self._ui(self._set_progress, 1.0, col)
            self._ui(self._update_risk_strip, overall)
            self._ui(self.btn_export.configure, {"state": "normal"})
            self._ui(self.footer_var.set,
                f"scan complete  //  {target}  //  "
                f"{len(self._enriched)} service(s)  //  "
                f"risk {overall['score']}/10 — {sev}"
            )

        self._log("Done.", "good", record)
        self._save_to_history(record)
        self._finish(record)

    # ═══════════════════════════════════════════════════════════════
    # TREE
    # ═══════════════════════════════════════════════════════════════

    def _add_tree_row(self, r):
        sev = r["risk"]["severity"]
        parent = self.tree.insert("", "end",
            text="▶",
            values=(
                r["port"], r["protocol"],
                r["service"],
                r["product"] or "—",
                r["version"] or "—",
                r["risk"]["cve_count"],
                r["risk"]["score"],
                sev,
            ),
            tags=(sev,),
            open=False,
        )

        # severity breakdown child
        self.tree.insert(parent, "end",
            values=("", "",
                f"CRIT {r['risk']['critical']}  "
                f"HIGH {r['risk']['high']}  "
                f"MED {r['risk']['medium']}  "
                f"LOW {r['risk']['low']}",
                "", "", "", "", ""),
            tags=("CVE_HEAD",),
        )

        # top CVEs
        for cve in r.get("cves", [])[:8]:
            cs = cve.get("severity", "")
            self.tree.insert(parent, "end",
                values=(
                    "", "",
                    cve["id"],
                    cve.get("description", "")[:55] + "…",
                    "", "",
                    cve.get("score", ""),
                    cs,
                ),
                tags=(cs if cs in SEV_COLOR else "CVE_ROW",),
            )

    def _update_risk_strip(self, overall):
        sev   = overall["severity"]
        color = SEV_COLOR.get(sev, FG_MID)
        self.risk_var.set(
            f"overall risk score:  {overall['score']} / 10  —  {sev}"
        )
        self.risk_strip.configure(bg=BG_INPUT)
        for widget in self.risk_strip.winfo_children():
            widget.configure(fg=color)

    # ═══════════════════════════════════════════════════════════════
    # FINISH / CLOCK
    # ═══════════════════════════════════════════════════════════════

    def _finish(self, record=None):
        self._scanning = False
        self.root.after(0, self.btn_start.configure,  {"state": "normal"})
        self.root.after(0, self.btn_stop.configure,   {"state": "disabled"})
        self.root.after(0, self.status_var.set, "DONE")
        self._stop_flag = False

    def _tick_clock(self):
        self._clock_var.set(
            datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        )
        self.root.after(1000, self._tick_clock)


# ── entry ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    app  = PortMortemApp(root)
    root.mainloop()