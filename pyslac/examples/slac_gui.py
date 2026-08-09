"""
SLAC IBE Demo GUI — Windows 98 Style
VehicleSecProject — University of Alabama

Run: sudo python slac_gui.py
"""

import tkinter as tk
from tkinter import font as tkfont
import threading
import subprocess
import time
import os
import sys

# ── Paths ────────────────────────────────────────────────────
PROJECT_DIR  = "/home/jack/projects/noninteractive-ibc-slac"
VENV_PYTHON  = f"{PROJECT_DIR}/venv/bin/python"
EVSE_SCRIPT  = f"{PROJECT_DIR}/pyslac/examples/single_slac_session.py"
PEV_SCRIPT   = f"{PROJECT_DIR}/pyslac/examples/ev_slac_scapy.py"
IBE_SECRET_EV   = f"{PROJECT_DIR}/ibe_master_secret_ev.bin"
IBE_SECRET_EVSE = f"{PROJECT_DIR}/ibe_master_secret_evse.bin"
IBE_GENERATOR   = f"{PROJECT_DIR}/ibe_generator.bin"
IFACE        = "eno1"
BOARD_PEV    = "88:FC:A6:1C:81:C2"
BOARD_EVSE   = "88:FC:A6:1C:81:BB"

# ── Win98 Color Palette ──────────────────────────────────────
WIN98 = {
    "bg":          "#C0C0C0",
    "title_bar":   "#000080",
    "title_text":  "#FFFFFF",
    "btn_face":    "#C0C0C0",
    "btn_shadow":  "#808080",
    "btn_hilite":  "#FFFFFF",
    "black":       "#000000",
    "white":       "#FFFFFF",
    "sunken_bg":   "#FFFFFF",
    "green":       "#008000",
    "red":         "#800000",
    "blue":        "#000080",
    "yellow":      "#808000",
    "teal":        "#008080",
    "console_bg":  "#000000",
    "console_fg":  "#C0C0C0",
    "evse_col":    "#00FF00",
    "pev_col":     "#00FFFF",
    "ibe_col":     "#FFFF00",
    "step_col":    "#FF8000",
    "error_col":   "#FF0000",
    "ok_col":      "#00FF00",
}

# # ── SLAC Steps ───────────────────────────────────────────────
# STEPS = [
#     #("1",  "CM_SET_KEY",              "EVSE→Chip",  "existing"),
#     ("1",  "CM_SLAC_PARM.REQ",        "PEV→EVSE",   "existing"),
#     ("2",  "CM_SLAC_PARM.CNF",        "EVSE→PEV",   "existing"),
#     ("3",  "CM_START_ATTEN_CHAR.IND", "PEV→BC",     "existing"),
#     ("4",  "CM_MNBC_SOUND.IND",       "PEV→BC",     "existing"),
#     ("5",  "CM_ATTEN_CHAR.IND",       "EVSE→PEV",   "existing"),
#     ("6",  "CM_ATTEN_CHAR.RSP",       "PEV→EVSE",   "existing"),
#     ("7",  "IBE KEY ESTABLISH",       "LOCAL",      "ibe"),
#     ("8",  "CM_SLAC_MATCH.REQ",       "PEV→EVSE",   "existing"),
#     ("9",  "CM_SLAC_MATCH.CNF",       "EVSE→PEV",   "existing"),
# ]


STEPS = [
    ("1",  "CM_SLAC_PARM.REQ",        "PEV→EVSE",   "existing"),
    ("2",  "CM_SLAC_PARM.CNF",        "EVSE→PEV",   "existing"),
    ("3",  "CM_START_ATTEN_CHAR.IND", "PEV→BC",     "existing"),
    ("4",  "CM_MNBC_SOUND.IND",       "PEV→BC",     "existing"),
    ("5",  "CM_ATTEN_CHAR.IND",       "EVSE→PEV",   "existing"),
    ("6",  "CM_ATTEN_CHAR.RSP",       "PEV→EVSE",   "existing"),
    ("7",  "CM_SLAC_MATCH.REQ",       "PEV→EVSE",   "existing"),
    ("8",  "CM_SLAC_MATCH.CNF",       "EVSE→PEV",   "existing"),
]


# # ── Step trigger keywords ────────────────────────────────────
# STEP_TRIGGERS = {
#     #"CM_SET_KEY: Finished":               0,
#     "Sent Param Request":                 0,
#     "Sent SLAC_PARM.CNF":                 1,
#     "Sent Attenuation Characterization Indication": 2,
#     "Sent MNBC Sound Indication":         3,
#     "Sent ATTEN_CHAR.IND":                4,
#     "Sent Attenuation Characterization Response": 5,
#     "IBE KEY ESTABLISHMENT":              6,
#     "Sending Slac Match":                 7,
#     "Sent CM_SLAC_MATCH.CNF":             8,
# }


STEP_TRIGGERS = {
    "Sent Param Request":                           0,
    "Sent SLAC_PARM.CNF":                           1,
    "Sent Attenuation Characterization Indication": 2,
    "Sent MNBC Sound Indication":                   3,
    "Sent ATTEN_CHAR.IND":                          4,
    "Sent Attenuation Characterization Response":   5,
    "Sending Slac Match":                           6,
    "Sent CM_SLAC_MATCH.CNF":                       7,
}


class Win98Button(tk.Frame):
    """Classic Windows 98 raised button"""
    def __init__(self, parent, text, command=None, width=120, **kwargs):
        super().__init__(parent, bd=0, bg=WIN98["bg"])
        self._cmd = command
        self._pressed = False

        self.canvas = tk.Canvas(self, width=width, height=23,
                                bg=WIN98["bg"], highlightthickness=0)
        self.canvas.pack()
        self._draw_up()
        self._label_id = self.canvas.create_text(
            width//2, 11, text=text,
            font=("MS Sans Serif", 8), fill=WIN98["black"]
        )
        self.canvas.bind("<ButtonPress-1>",   self._press)
        self.canvas.bind("<ButtonRelease-1>", self._release)

    def _draw_up(self):
        self.canvas.delete("border")
        w = int(self.canvas["width"])
        h = int(self.canvas["height"])
        self.canvas.create_rectangle(0, 0, w-1, h-1,
            fill=WIN98["btn_face"], outline="", tags="border")
        # top/left highlight
        self.canvas.create_line(0,0,w-1,0, fill=WIN98["btn_hilite"], tags="border")
        self.canvas.create_line(0,0,0,h-1, fill=WIN98["btn_hilite"], tags="border")
        # bottom/right shadow
        self.canvas.create_line(1,h-2,w-1,h-2, fill=WIN98["btn_shadow"], tags="border")
        self.canvas.create_line(w-2,1,w-2,h-1, fill=WIN98["btn_shadow"], tags="border")
        self.canvas.create_line(0,h-1,w,h-1,   fill=WIN98["black"],      tags="border")
        self.canvas.create_line(w-1,0,w-1,h,   fill=WIN98["black"],      tags="border")

    def _draw_down(self):
        self.canvas.delete("border")
        w = int(self.canvas["width"])
        h = int(self.canvas["height"])
        self.canvas.create_rectangle(0,0,w-1,h-1,
            fill=WIN98["btn_face"], outline="", tags="border")
        self.canvas.create_line(0,0,w-1,0, fill=WIN98["black"],      tags="border")
        self.canvas.create_line(0,0,0,h-1, fill=WIN98["black"],      tags="border")
        self.canvas.create_line(1,1,w-2,1, fill=WIN98["btn_shadow"], tags="border")
        self.canvas.create_line(1,1,1,h-2, fill=WIN98["btn_shadow"], tags="border")

    def _press(self, e):
        self._draw_down()
        self.canvas.move(self._label_id, 1, 1)

    def _release(self, e):
        self._draw_up()
        self.canvas.move(self._label_id, -1, -1)
        if self._cmd:
            self._cmd()

    def set_text(self, t):
        self.canvas.itemconfig(self._label_id, text=t)

    def set_state(self, state):
        color = WIN98["btn_shadow"] if state == "disabled" else WIN98["black"]
        self.canvas.itemconfig(self._label_id, fill=color)
        if state == "disabled":
            self._cmd = None


class Win98GroupBox(tk.LabelFrame):
    def __init__(self, parent, text, **kwargs):
        super().__init__(parent, text=text,
                         bg=WIN98["bg"],
                         fg=WIN98["black"],
                         font=("MS Sans Serif", 8),
                         bd=2, relief="groove",
                         **kwargs)


class SLACDemoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SLAC IBE Demo — VehicleSecProject")
        self.root.configure(bg=WIN98["bg"])
        self.root.resizable(True, True)

        self.evse_proc  = None
        self.pev_proc   = None
        self.reset_thread = None
        self.steps_done = set()
        self.matched    = False

        self._build_title_bar()
        self._build_main()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)




    # ── Title Bar ────────────────────────────────────────────
    def _build_title_bar(self):
        bar = tk.Frame(self.root, bg=WIN98["title_bar"], height=20)
        bar.pack(fill="x", side="top")
        tk.Label(bar, text="IBC SLAC GUI",
                 bg=WIN98["title_bar"], fg=WIN98["title_text"],
                 font=("MS Sans Serif", 8, "bold")).pack(side="left", padx=4)
        close = tk.Button(bar, text="✕", bg=WIN98["btn_face"],
                          fg=WIN98["black"], font=("MS Sans Serif", 7, "bold"),
                          relief="raised", bd=1, width=2,
                          command=self._on_close)
        close.pack(side="right", padx=2, pady=1)

    # ── Main Layout ──────────────────────────────────────────
    def _build_main(self):
        # Top: status bar
        self._build_status_bar()

        # Middle: diagram + controls side by side
        mid = tk.Frame(self.root, bg=WIN98["bg"])
        mid.pack(fill="both", expand=True, padx=4, pady=2)

        self._build_diagram(mid)
        self._build_controls(mid)

        # Bottom: consoles
        self._build_consoles()

    # ── Status Bar ───────────────────────────────────────────
    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg=WIN98["bg"], bd=1, relief="sunken")
        bar.pack(fill="x", padx=4, pady=2)

        self.status_var = tk.StringVar(value="Ready. Reset boards before starting.")
        tk.Label(bar, textvariable=self.status_var,
                 bg=WIN98["bg"], fg=WIN98["black"],
                 font=("MS Sans Serif", 8),
                 anchor="w").pack(side="left", padx=4)

        self.led = tk.Canvas(bar, width=14, height=14,
                             bg=WIN98["bg"], highlightthickness=0)
        self.led.pack(side="right", padx=6)
        self._led_id = self.led.create_oval(2,2,12,12, fill=WIN98["btn_shadow"])

    def _set_status(self, msg, color="black"):
        self.status_var.set(msg)
        led_colors = {
            "black": WIN98["btn_shadow"],
            "green": "#00CC00",
            "red":   "#CC0000",
            "yellow":"#CCCC00",
        }
        self.led.itemconfig(self._led_id, fill=led_colors.get(color, WIN98["btn_shadow"]))

    # ── Sequence Diagram ─────────────────────────────────────
    def _build_diagram(self, parent):
        grp = Win98GroupBox(parent, "SLAC Protocol Sequence")
        grp.pack(side="left", fill="both", expand=True, padx=2, pady=2)

        self.diag = tk.Canvas(grp, width=500, height=400,
                              bg=WIN98["sunken_bg"],
                              highlightthickness=1,
                              highlightbackground=WIN98["btn_shadow"])
        self.diag.pack(padx=4, pady=4, fill="both", expand=True)
        self._draw_diagram_base()

    def _draw_diagram_base(self):
        c = self.diag
        c.delete("all")

        # Columns
        PEV_X  = 110
        EVSE_X = 390

        # Headers
        c.create_rectangle(PEV_X-50, 5, PEV_X+50, 25,
                           fill=WIN98["teal"], outline=WIN98["black"])
        c.create_text(PEV_X, 15, text="PEV (Board1)",
                      font=("MS Sans Serif", 8, "bold"), fill=WIN98["white"])

        c.create_rectangle(EVSE_X-55, 5, EVSE_X+55, 25,
                           fill=WIN98["blue"], outline=WIN98["black"])
        c.create_text(EVSE_X, 15, text="EVSE (Board2)",
                      font=("MS Sans Serif", 8, "bold"), fill=WIN98["white"])

        # Lifelines
        #c.create_line(PEV_X, 26, PEV_X, 330, dash=(4,3), fill=WIN98["btn_shadow"])
        #c.create_line(EVSE_X, 26, EVSE_X, 330, dash=(4,3), fill=WIN98["btn_shadow"])

        c.create_line(PEV_X, 26, PEV_X, 400, dash=(4,3), fill="#404040", width=2)
        c.create_line(EVSE_X, 26, EVSE_X, 400, dash=(4,3), fill="#404040", width=2)

        # Step rows
        self._step_y = {}
        for i, (num, name, direction, kind) in enumerate(STEPS):
            y = 50 + i * 36
            self._step_y[i] = y

            # Step number box
            c.create_rectangle(2, y-8, 20, y+8,
                               fill=WIN98["btn_face"], outline=WIN98["btn_shadow"])
            c.create_text(11, y, text=num,
                          font=("MS Sans Serif", 7), fill=WIN98["black"])

            # Placeholder dimmed arrow
            if direction in ("PEV→EVSE", "PEV→BC"):
                x1, x2 = PEV_X, EVSE_X
            elif direction == "EVSE→PEV":
                x1, x2 = EVSE_X, PEV_X
            elif direction == "EVSE→Chip":
                x1, x2 = EVSE_X, EVSE_X + 40
            else:  # LOCAL
                x1, x2 = PEV_X + 10, EVSE_X - 10

            c.create_line(x1, y, x2, y,
              fill="#888888", arrow=tk.LAST if x2 != x1 else tk.NONE,
              dash=(2,3), width=2, tags=f"dim_{i}")
            c.create_text((x1+x2)//2, y-9, text=name,
              font=("MS Sans Serif", 7, "bold"), fill="#555555",)

        self.PEV_X  = PEV_X
        self.EVSE_X = EVSE_X

    def _activate_step(self, idx):
        if idx in self.steps_done:
            return
        self.steps_done.add(idx)
        c    = self.diag
        num, name, direction, kind = STEPS[idx]
        y    = self._step_y[idx]

        # Delete dim placeholder
        c.delete(f"dim_{idx}")
        c.delete(f"dimlbl_{idx}")

        # Color by kind
        colors = {
            "existing": WIN98["blue"],
            "ibe":      "#FF8C00",
            "new":      WIN98["green"],
        }
        col = colors.get(kind, WIN98["black"])

        PEV_X  = self.PEV_X
        EVSE_X = self.EVSE_X

        if direction == "PEV→EVSE" or direction == "PEV→BC":
            x1, x2 = PEV_X, EVSE_X
            c.create_line(x1, y, x2, y, fill=col, arrow=tk.LAST, width=3)
        elif direction == "EVSE→PEV":
            x1, x2 = EVSE_X, PEV_X
            c.create_line(x1, y, x2, y, fill=col, arrow=tk.LAST, width=3)
        elif direction == "EVSE→Chip":
            x1, x2 = EVSE_X, EVSE_X + 38
            c.create_line(x1, y, x2, y, fill=col, arrow=tk.LAST, width=3)
            c.create_text(x2+2, y, text="chip", font=("MS Sans Serif", 6),
                          fill=col, anchor="w")
        elif direction == "LOCAL":
            # Double-headed arrow on both lifelines
            c.create_rectangle(PEV_X-30, y-8, EVSE_X+30, y+8,
                               fill="#FFF3CC", outline="#FF8C00", width=1)
            c.create_text((PEV_X+EVSE_X)//2, y,
                          text="IBE — NO WIRE TRAFFIC",
                          font=("MS Sans Serif", 7, "bold"), fill="#FF6600")

        # Label
        if direction != "LOCAL":
            c.create_text((x1+x2)//2, y-9, text=name,
                          font=("MS Sans Serif", 7, "bold"), fill=col)

        # Flash effect
        c.create_rectangle(self.PEV_X-55, y-10, self.EVSE_X+55, y+10,
                           fill="#FFFFCC", outline="", tags="flash")
        c.after(300, lambda: c.delete("flash"))

    
    
    def _show_ibc_local(self):
        c = self.diag
        PEV_X  = self.PEV_X
        EVSE_X = self.EVSE_X
        # Find y position between step 5 (idx 5) and step 6 (idx 6)
        y = (self._step_y[5] + self._step_y[6]) // 2

        # PEV side box
        c.create_rectangle(PEV_X-45, y-16, PEV_X+45, y+16,
                        fill="#fff0f0", outline="#9E1B32", width=2)
        c.create_text(PEV_X, y-5, text="IBC Key",
                    font=("MS Sans Serif", 7, "bold"), fill="#9E1B32")
        c.create_text(PEV_X, y+6, text="Establishment",
                    font=("MS Sans Serif", 7, "bold"), fill="#9E1B32")

        # EVSE side box
        c.create_rectangle(EVSE_X-45, y-16, EVSE_X+45, y+16,
                        fill="#fff0f0", outline="#9E1B32", width=2)
        c.create_text(EVSE_X, y-5, text="IBC Key",
                    font=("MS Sans Serif", 7, "bold"), fill="#9E1B32")
        c.create_text(EVSE_X, y+6, text="Establishment",
                    font=("MS Sans Serif", 7, "bold"), fill="#9E1B32")
    
    
    
    def _show_matched(self):
        c = self.diag
        c.create_rectangle(self.PEV_X-55, 378, self.EVSE_X+55, 398,
                           fill="#00AA00", outline=WIN98["black"])
        c.create_text((self.PEV_X+self.EVSE_X)//2, 328,
                      text="✓  PEV-EVSE MATCHED",
                      font=("MS Sans Serif", 8, "bold"), fill=WIN98["white"])

    # ── Controls Panel ───────────────────────────────────────
    def _build_controls(self, parent):
        panel = tk.Frame(parent, bg=WIN98["bg"], width=200)
        panel.pack(side="right", fill="y", padx=2, pady=2)
        panel.pack_propagate(False)

        # ── Reset Group ──────────────────────────────────────
        grp_reset = Win98GroupBox(panel, "1. Board Reset")
        grp_reset.pack(fill="x", padx=2, pady=4)

        tk.Label(grp_reset,
                 text="Factory reset both boards\nand delete IBE key files.\nWait 60s for PLC re-pair.",
                 bg=WIN98["bg"], fg=WIN98["black"],
                 font=("MS Sans Serif", 7),
                 justify="left").pack(anchor="w", padx=4, pady=2)

        self.btn_reset = Win98Button(grp_reset, "Reset Boards", self._do_reset, width=150)
        self.btn_reset.pack(padx=4, pady=4)

        # Progress bar
        pb_frame = tk.Frame(grp_reset, bg=WIN98["btn_shadow"],
                            bd=1, relief="sunken")
        pb_frame.pack(fill="x", padx=4, pady=2)
        self.pb_canvas = tk.Canvas(pb_frame, height=14, bg=WIN98["sunken_bg"],
                                   highlightthickness=0)
        self.pb_canvas.pack(fill="x")
        self._pb_bar = self.pb_canvas.create_rectangle(
            0, 0, 0, 14, fill=WIN98["blue"], outline="")
        self._pb_text = self.pb_canvas.create_text(
            75, 7, text="", font=("MS Sans Serif", 7), fill=WIN98["black"])

        # PLC link indicator
        link_frame = tk.Frame(grp_reset, bg=WIN98["bg"])
        link_frame.pack(fill="x", padx=4, pady=2)
        tk.Label(link_frame, text="PLC Link:",
                 bg=WIN98["bg"], font=("MS Sans Serif", 7)).pack(side="left")
        self.link_canvas = tk.Canvas(link_frame, width=14, height=14,
                                     bg=WIN98["bg"], highlightthickness=0)
        self.link_canvas.pack(side="left", padx=2)
        self._link_led = self.link_canvas.create_oval(
            2,2,12,12, fill=WIN98["btn_shadow"])
        self.link_label = tk.Label(link_frame, text="Unknown",
                                   bg=WIN98["bg"], font=("MS Sans Serif", 7))
        self.link_label.pack(side="left")

        # ── Run Group ────────────────────────────────────────
        grp_run = Win98GroupBox(panel, "2. Run SLAC+IBE")
        grp_run.pack(fill="x", padx=2, pady=4)

        tk.Label(grp_run,
                 text="Start EVSE then PEV.\nBoth run simultaneously.",
                 bg=WIN98["bg"], fg=WIN98["black"],
                 font=("MS Sans Serif", 7),
                 justify="left").pack(anchor="w", padx=4, pady=2)

        self.btn_run = Win98Button(grp_run, "Start Session", self._do_run, width=150)
        self.btn_run.pack(padx=4, pady=2)

        self.btn_stop = Win98Button(grp_run, "Stop", self._do_stop, width=150)
        self.btn_stop.pack(padx=4, pady=2)

        # Process indicators
        proc_frame = tk.Frame(grp_run, bg=WIN98["bg"])
        proc_frame.pack(fill="x", padx=4, pady=2)

        tk.Label(proc_frame, text="EVSE:",
                 bg=WIN98["bg"], font=("MS Sans Serif", 7)).grid(row=0, column=0, sticky="w")
        self.evse_led_c = tk.Canvas(proc_frame, width=12, height=12,
                                    bg=WIN98["bg"], highlightthickness=0)
        self.evse_led_c.grid(row=0, column=1, padx=2)
        self._evse_led = self.evse_led_c.create_oval(1,1,11,11, fill=WIN98["btn_shadow"])

        tk.Label(proc_frame, text="PEV:",
                 bg=WIN98["bg"], font=("MS Sans Serif", 7)).grid(row=1, column=0, sticky="w")
        self.pev_led_c = tk.Canvas(proc_frame, width=12, height=12,
                                   bg=WIN98["bg"], highlightthickness=0)
        self.pev_led_c.grid(row=1, column=1, padx=2)
        self._pev_led = self.pev_led_c.create_oval(1,1,11,11, fill=WIN98["btn_shadow"])

        # ── Info Group ───────────────────────────────────────
        grp_info = Win98GroupBox(panel, "Board Info")
        grp_info.pack(fill="x", padx=2, pady=4)

        info = (
            f"PEV  MAC: {BOARD_PEV}\n"
            f"EVSE MAC: {BOARD_EVSE}\n"
            f"Iface: {IFACE}\n"
            f"IBE: Boneh-Franklin SS512\n"
            f"Protocol: ISO 15118-3"
        )
        tk.Label(grp_info, text=info,
                 bg=WIN98["bg"], fg=WIN98["black"],
                 font=("MS Sans Serif", 7),
                 justify="left").pack(anchor="w", padx=4, pady=2)

        # ── Clear button ─────────────────────────────────────
        self.btn_clear = Win98Button(panel, "Clear Logs", self._clear_logs, width=150)
        self.btn_clear.pack(padx=4, pady=8)

    # ── Consoles ─────────────────────────────────────────────
    def _build_consoles(self):
        grp = Win98GroupBox(self.root, "Console Output")
        grp.pack(fill="both", expand=True, padx=4, pady=2)

        nb = tk.Frame(grp, bg=WIN98["bg"])
        nb.pack(fill="both", expand=True)

        # Tab buttons
        tab_bar = tk.Frame(nb, bg=WIN98["bg"])
        tab_bar.pack(fill="x")

        self._tab_frames = {}
        self._tab_btns   = {}
        self._active_tab = tk.StringVar(value="EVSE")

        for name in ["EVSE", "PEV", "Reset"]:
            btn = tk.Button(tab_bar, text=name,
                            font=("MS Sans Serif", 8),
                            bg=WIN98["btn_face"], fg=WIN98["black"],
                            relief="raised", bd=2,
                            command=lambda n=name: self._switch_tab(n))
            btn.pack(side="left", padx=1)
            self._tab_btns[name] = btn

        # Console frames
        console_holder = tk.Frame(nb, bg=WIN98["bg"])
        console_holder.pack(fill="both", expand=True)

        for name in ["EVSE", "PEV", "Reset"]:
            f = tk.Frame(console_holder, bg=WIN98["bg"])
            txt = tk.Text(f, height=10, bg=WIN98["console_bg"],
                          fg=WIN98["console_fg"],
                          font=("Courier New", 8),
                          insertbackground=WIN98["console_fg"],
                          state="disabled", wrap="word",
                          relief="sunken", bd=2)
            sb = tk.Scrollbar(f, command=txt.yview)
            txt.configure(yscrollcommand=sb.set)
            sb.pack(side="right", fill="y")
            txt.pack(side="left", fill="both", expand=True)

            # Tags
            txt.tag_config("evse",  foreground="#00FF00")
            txt.tag_config("pev",   foreground="#00FFFF")
            txt.tag_config("ibe",   foreground="#FFFF00")
            txt.tag_config("step",  foreground="#FF8C00")
            txt.tag_config("error", foreground="#FF4444")
            txt.tag_config("ok",    foreground="#00FF00")
            txt.tag_config("dim",   foreground="#808080")
            txt.tag_config("white", foreground="#FFFFFF")

            self._tab_frames[name] = (f, txt)

        self._switch_tab("EVSE")

    def _switch_tab(self, name):
        for n, (f, _) in self._tab_frames.items():
            f.pack_forget()
            self._tab_btns[n].config(relief="raised", bg=WIN98["btn_face"])
        frame, _ = self._tab_frames[name]
        frame.pack(fill="both", expand=True)
        self._tab_btns[name].config(relief="sunken", bg=WIN98["btn_shadow"])
        self._active_tab.set(name)

    def _log(self, console_name, msg, tag="white"):
        _, txt = self._tab_frames[console_name]
        txt.configure(state="normal")
        txt.insert("end", msg + "\n", tag)
        txt.see("end")
        txt.configure(state="disabled")

    def _clear_logs(self):
        for name in ["EVSE", "PEV", "Reset"]:
            _, txt = self._tab_frames[name]
            txt.configure(state="normal")
            txt.delete("1.0", "end")
            txt.configure(state="disabled")

    # ── Progress Bar ─────────────────────────────────────────
    def _set_progress(self, pct, label=""):
        self.pb_canvas.update_idletasks()
        w = self.pb_canvas.winfo_width()
        bar_w = int(w * pct / 100)
        self.pb_canvas.coords(self._pb_bar, 0, 0, bar_w, 14)
        self.pb_canvas.itemconfig(self._pb_text, text=label)

    # ── Reset Logic ──────────────────────────────────────────
    def _do_reset(self):
        if self.reset_thread and self.reset_thread.is_alive():
            return
        self.btn_reset.set_state("disabled")
        self.btn_run.set_state("disabled")
        self.reset_thread = threading.Thread(target=self._reset_worker, daemon=True)
        self.reset_thread.start()

    def _reset_worker(self):
        self._set_status("Resetting boards...", "yellow")
        self._log("Reset", "="*50, "step")
        self._log("Reset", "  BOARD RESET + IBE KEY CLEANUP", "step")
        self._log("Reset", "="*50, "step")

        # Delete IBE files
        self._log("Reset", "\n[1/4] Deleting IBE key files...", "dim")
        for f in [IBE_SECRET_EV, IBE_SECRET_EVSE, IBE_GENERATOR]:
            if os.path.exists(f):
                os.remove(f)
                self._log("Reset", f"  Deleted: {os.path.basename(f)}", "ok")
            else:
                self._log("Reset", f"  Not found: {os.path.basename(f)}", "dim")
        self._set_progress(10, "IBE files deleted")

        # Factory reset boards
        self._log("Reset", "\n[2/4] Factory resetting boards...", "dim")
        for mac, name in [(BOARD_EVSE, "EVSE Board2"), (BOARD_PEV, "PEV Board1")]:
            self._log("Reset", f"  Resetting {name} ({mac})...", "dim")
            r = subprocess.run(
                ["sudo", "plctool", "-i", IFACE, "-T", mac],
                capture_output=True, text=True
            )
            if r.returncode == 0 or "Restoring" in r.stdout:
                self._log("Reset", f"  ✓ {name} reset sent", "ok")
            else:
                self._log("Reset", f"  ✗ {name}: {r.stderr.strip()}", "error")
            time.sleep(2)
        self._set_progress(20, "Boards reset")

        # Wait 60 seconds
        self._log("Reset", "\n[3/4] Waiting 60s for boards to auto-pair...", "dim")
        for i in range(60, 0, -1):
            pct = 20 + int(70 * (60 - i) / 60)
            self._set_progress(pct, f"Settling... {i}s")
            self._log("Reset", f"  {i}s remaining...", "dim") if i % 10 == 0 else None
            time.sleep(1)
        self._set_progress(90, "Checking link...")

        # Verify PLC link
        self._log("Reset", "\n[4/4] Verifying PLC link...", "dim")
        r = subprocess.run(
            ["sudo", "plctool", "-i", IFACE, "-m", BOARD_PEV],
            capture_output=True, text=True
        )
        if "009 mbps" in r.stdout or "009 Mbps" in r.stdout:
            self._log("Reset", "  ✓ PLC link confirmed at 9 Mbps", "ok")
            self._set_progress(100, "Ready!")
            self._set_status("Boards ready — PLC link at 9 Mbps", "green")
            self.root.after(0, lambda: self.link_canvas.itemconfig(
                self._link_led, fill="#00CC00"))
            self.root.after(0, lambda: self.link_label.config(text="9 Mbps ✓"))
        else:
            self._log("Reset", "  ✗ PLC link not confirmed", "error")
            self._log("Reset", r.stdout[:200], "dim")
            self._set_progress(100, "Link check failed")
            self._set_status("PLC link not confirmed — check boards", "red")
            self.root.after(0, lambda: self.link_canvas.itemconfig(
                self._link_led, fill="#CC0000"))
            self.root.after(0, lambda: self.link_label.config(text="No link ✗"))

        self._log("Reset", "\n" + "="*50, "step")
        self._log("Reset", "  Reset complete. Click 'Start Session'.", "ok")
        self._log("Reset", "="*50, "step")

        # Re-enable buttons
        self.root.after(0, self._reenable_buttons)

    def _reenable_buttons(self):
        self.btn_reset = self._remake_btn(
            self.btn_reset, "Reset Boards", self._do_reset)
        self.btn_run = self._remake_btn(
            self.btn_run, "Start Session", self._do_run)

    def _remake_btn(self, old_btn, text, cmd):
        parent = old_btn.master
        old_btn.destroy()
        btn = Win98Button(parent, text, cmd, width=150)
        btn.pack(padx=4, pady=2)
        return btn

    # ── Run Logic ────────────────────────────────────────────
    def _do_run(self):
        if self.evse_proc or self.pev_proc:
            self._set_status("Session already running", "yellow")
            return

        # Reset diagram
        self.steps_done.clear()
        self.matched = False
        self._draw_diagram_base()
        self._set_status("Starting SLAC+IBE session...", "yellow")
        self._switch_tab("EVSE")

        # Update LEDs
        self.evse_led_c.itemconfig(self._evse_led, fill="#CCCC00")
        self.pev_led_c.itemconfig(self._pev_led,  fill="#CCCC00")

        threading.Thread(target=self._run_evse_worker, daemon=True).start()
        threading.Thread(target=self._run_pev_worker,  daemon=True).start()

    def _run_evse_worker(self):
        self._log("EVSE", "="*50, "step")
        self._log("EVSE", "  EVSE SESSION STARTING", "step")
        self._log("EVSE", "="*50, "step")

        try:
            self.evse_proc = subprocess.Popen(
                ["sudo", VENV_PYTHON, "-u", EVSE_SCRIPT],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=PROJECT_DIR
            )
            self.evse_led_c.itemconfig(self._evse_led, fill="#00CC00")

            for line in self.evse_proc.stdout:
                
                line = line.rstrip()
                if not line:
                    continue

                # Classify line
                tag = "evse"
                if any(k in line for k in ["ERROR", "error", "failed", "Failed"]):
                    tag = "error"
                elif any(k in line for k in ["IBE KEY", "Pairing", "NMK", "SK_EVSE"]):
                    tag = "ibe"
                elif any(k in line for k in ["STEP", "═", "▶"]):
                    tag = "step"
                elif "Matched" in line or "MATCHED" in line:
                    tag = "ok"

                self._log("EVSE", line, tag)

                # Check step triggers
                for trigger, step_idx in STEP_TRIGGERS.items():
                    if trigger in line:
                        if "IBC KEY ESTABLISHMENT" in line or "IBE KEY ESTABLISHMENT" in line:
                            self.root.after(0, self._show_ibc_local)
                        self.root.after(0, lambda i=step_idx: self._activate_step(i))
                        break

                if "MATCHED Successfully" in line:
                    self.matched = True
                    self.root.after(0, self._show_matched)
                    self.root.after(0, lambda: self._set_status(
                        "PEV-EVSE MATCHED ✓  IBE handshake complete", "green"))

            self.evse_proc.wait()
            rc = self.evse_proc.returncode
            self._log("EVSE", f"\n[EVSE process exited: code {rc}]",
                      "ok" if rc == 0 else "error")

        except Exception as e:
            self._log("EVSE", f"EVSE error: {e}", "error")
        finally:
            self.evse_proc = None
            self.root.after(0, lambda: self.evse_led_c.itemconfig(
                self._evse_led, fill=WIN98["btn_shadow"]))

    def _run_pev_worker(self):
        time.sleep(15)  # EVSE needs a head start

        self._log("PEV", "="*50, "step")
        self._log("PEV", "  PEV SESSION STARTING", "step")
        self._log("PEV", "="*50, "step")

        try:
            self.pev_proc = subprocess.Popen(
                ["sudo", VENV_PYTHON, "-u", PEV_SCRIPT],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=PROJECT_DIR
            )
            self.pev_led_c.itemconfig(self._pev_led, fill="#00CC00")

            for line in self.pev_proc.stdout:
                line = line.rstrip()
                if not line:
                    continue

                tag = "pev"
                if any(k in line for k in ["ERROR", "error", "failed", "Failed"]):
                    tag = "error"
                elif any(k in line for k in ["IBE KEY", "Pairing", "NMK", "SK_EV"]):
                    tag = "ibe"
                elif any(k in line for k in ["STEP", "═", "▶"]):
                    tag = "step"
                elif "MATCHED" in line or "HANDSHAKE COMPLETE" in line:
                    tag = "ok"

                self._log("PEV", line, tag)

            self.pev_proc.wait()
            rc = self.pev_proc.returncode
            self._log("PEV", f"\n[PEV process exited: code {rc}]",
                      "ok" if rc == 0 else "error")

        except Exception as e:
            self._log("PEV", f"PEV error: {e}", "error")
        finally:
            self.pev_proc = None
            self.root.after(0, lambda: self.pev_led_c.itemconfig(
                self._pev_led, fill=WIN98["btn_shadow"]))

    def _do_stop(self):
        self._set_status("Stopping processes...", "yellow")
        for proc in [self.evse_proc, self.pev_proc]:
            if proc:
                try:
                    subprocess.run(["sudo", "kill", str(proc.pid)],
                                   capture_output=True)
                except:
                    pass
        self.evse_proc = None
        self.pev_proc  = None
        self.evse_led_c.itemconfig(self._evse_led, fill=WIN98["btn_shadow"])
        self.pev_led_c.itemconfig(self._pev_led,   fill=WIN98["btn_shadow"])
        self._set_status("Stopped.", "red")
        self._log("EVSE", "\n[Session stopped by user]", "error")
        self._log("PEV",  "\n[Session stopped by user]", "error")

    def _on_close(self):
        self._do_stop()
        self.root.destroy()


# ── Main ─────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("780x700")
    app = SLACDemoApp(root)
    root.mainloop()