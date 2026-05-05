import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import logging
import time

import pyslac
import pyslac.examples
import pyslac.examples.ev_slac_scapy
import pyslac.examples.single_slac_session


# Handles the logs from the SE side
class SELogHandler(logging.Handler):
    def __init__(self, widget):
        super().__init__()
        self.widget = widget
        self.define_tags()

    # Color codes the output logs
    def define_tags(self):
        self.widget.tag_config("existing", foreground="blue")
        self.widget.tag_config("new", foreground="green")
        self.widget.tag_config("error", foreground="red")
        self.widget.tag_config("default", foreground="white")

    def emit(self, record):
        global error_found
        msg = self.format(record)
        if record.getMessage()[:3] == "EV:":
            return

        tag = "default"
        # Draw arrows when specified logs are received
        if "Sent SLAC_PARM.CNF" in record.getMessage():
            draw_step("2: CM_SLAC_PARM.CNF")
            tag = "existing"
        elif "Sent ATTEN_CHAR.IND" in record.getMessage():
            draw_step("5: CM_ATTEN_CHAR.IND")
            tag = "existing"
        elif "Sent ECDH_EXCHANGE.REQ" in record.getMessage():
            draw_step("7: CM_ECDH_EXCHANGE.REQ")
            tag = "new"
        elif "Sent CM_SLAC_MATCH.CNF" in record.getMessage():
            draw_step("10: CM_SLAC_MATCH.CNF")
            tag = "existing"

        # Handle error logs
        if record.levelname == "ERROR":
            error_found = True
            draw_step("ERROR")
            tag = "error"
        self.widget.configure(state='normal')
        self.widget.insert(tk.END, msg + '\n', tag)
        self.widget.see(tk.END)
        self.widget.configure(state='disabled')


# Handles the logs from the EV side
class EVLogHandler(logging.Handler):
    def __init__(self, widget):
        super().__init__()
        self.widget = widget
        self.define_tags()

    # Color codes the output logs
    def define_tags(self):
        self.widget.tag_config("existing", foreground="lightblue")
        self.widget.tag_config("new", foreground="green")
        self.widget.tag_config("error", foreground="red")
        self.widget.tag_config("default", foreground="white")

    def emit(self, record):
        global error_found
        if record.getMessage()[:3] != "EV:":
            return
        msg = self.format(record)
        msg = msg[:13] + msg[16:]  # Removes EV: tag from msg (need to fix to work with non-debug logs) # noqa: E501

        tag = "default"
        # Draw arrows when specified logs are received
        if "Sent Param Request" in record.getMessage():
            draw_step("1: CM_SLAC_PARM.REQ")
            tag = "existing"
        elif "Sent Attenuation Characterization Indication" in record.getMessage():
            draw_step("3: CM_START_ATTEN_CHAR.IND")
            tag = "existing"
        elif "Sent MNBC Sound Indication" in record.getMessage():
            draw_step("4: CM_MNBC_SOUND.IND")
            tag = "existing"
        elif "Sent Attenuation Characterization Response" in record.getMessage():
            draw_step("6: CM_ATTEN_CHAR.RSP")
            tag = "existing"
        elif "Sending ECDH Exchange Response" in record.getMessage():
            draw_step("8: CM_ECDH_EXCHANGE.RSP")
            tag = "existing"
        elif "Sending Slac Match Request" in record.getMessage():
            draw_step("9: CM_SLAC_MATCH.REQ")
            tag = "existing"

        # Handle error logs
        if record.levelname == "ERROR":
            error_found = True
            draw_step("ERROR")
            tag = "error"

        self.widget.configure(state='normal')
        self.widget.insert(tk.END, msg + '\n', tag)
        self.widget.see(tk.END)
        self.widget.configure(state='disabled')


# Waits for step button to be pressed if not auto-run
def wait_for_step():
    if not auto_run.is_set():
        step_button.config(bg="green")
        step_event.wait()
        step_event.clear()
    else:
        time.sleep(0.5)


# Arrow Locations
message_arrows = {
    "1: CM_SLAC_PARM.REQ": [(200, 40, 500, 40), 0],
    "2: CM_SLAC_PARM.CNF": [(500, 70, 200, 70), 1],
    "3: CM_START_ATTEN_CHAR.IND": [(200, 100, 500, 100), 2],
    "4: CM_MNBC_SOUND.IND": [(200, 130, 500, 130), 3],
    "5: CM_ATTEN_CHAR.IND": [(500, 160, 200, 160), 4],
    "6: CM_ATTEN_CHAR.RSP": [(200, 190, 500, 190), 5],
    "7: CM_ECDH_EXCHANGE.REQ": [(200, 220, 500, 220), 6],
    "8: CM_ECDH_EXCHANGE.RSP": [(500, 250, 200, 250), 7],
    "9: CM_SLAC_MATCH.REQ": [(200, 280, 500, 280), 8],
    "10: CM_SLAC_MATCH.CNF": [(500, 310, 200, 310), 9],
}
drawn_arrows = {}


# Handles the drawing of arrows / error message
def draw_step(msg_type):
    global next_step
    if error_found:
        x1, y1, x2, y2 = message_arrows[steps[next_step]][0]  # Below the last-drawn arrow # noqa: E501
        mid_x = (x1 + x2) / 2
        mid_y = (y1 + y2) / 2 - 10  # slight vertical offset to avoid overlap
        label = canvas.create_text(mid_x, mid_y, text="ERROR: Check logs", font=('Arial', 10), fill="red")  # noqa: E501
        return
    if msg_type not in drawn_arrows and msg_type in message_arrows:
        x1, y1, x2, y2 = message_arrows[msg_type][0]
        next_step = max(next_step, message_arrows[msg_type][1] + 1)
        arrow = canvas.create_line(x1, y1, x2, y2, arrow=tk.LAST, fill='black', width=2)
        mid_x = (x1 + x2) / 2
        mid_y = (y1 + y2) / 2 - 10  # slight vertical offset to avoid overlap
        label_color = 'green' if "CM_ECDH_EXCHANGE" in msg_type else 'blue'  # Visual difference between existing and new steps # noqa: E501
        label = canvas.create_text(mid_x, mid_y, text=msg_type, font=('Arial', 10), fill=label_color)  # noqa: E501
        update_step_label()
        drawn_arrows[msg_type] = {arrow, label}


# SLAC Control
step_event = threading.Event()
auto_run = threading.Event()
next_step = 0

steps = [
    "1: CM_SLAC_PARM.REQ",
    "2: CM_SLAC_PARM.CNF",
    "3: CM_START_ATTEN_CHAR.IND",
    "4: CM_MNBC_SOUND.IND",
    "5: CM_ATTEN_CHAR.IND",
    "6: CM_ATTEN_CHAR.RSP",
    "7: CM_ECDH_EXCHANGE.REQ",
    "8: CM_ECDH_EXCHANGE.RSP",
    "9: CM_SLAC_MATCH.REQ",
    "10: CM_SLAC_MATCH.CNF"
]

# SLAC Control Functions
running = False
error_found = False


def start_slac():
    global running
    if running:
        messagebox.showwarning("Warning", "SLAC is already running.")
        return

    def se_slac_wrapper():
        global running, error_found
        try:
            running = True
            error_found = False
            # The lack of granularity here is why we only step through
            # EV communications
            pyslac.examples.single_slac_session.run()
        except Exception as e:
            error_found = True
            messagebox.showerror("Error", str(e))
        finally:
            running = False

    # Essentially recreates the EV run function but with more control
    def ev_slac_wrapper():
        global error_found
        try:
            pyslac.examples.ev_slac_scapy.setup()
            pyslac.examples.ev_slac_scapy.setKeyConfirmation()
            step_button.config(bg="gray40")
            time.sleep(20)
            wait_for_step()
            step_button.config(bg="gray90")
            pyslac.examples.ev_slac_scapy.paramRequest()
            wait_for_step()
            step_button.config(bg="gray90")
            pyslac.examples.ev_slac_scapy.attenChar()
            wait_for_step()
            step_button.config(bg="gray90")
            pyslac.examples.ev_slac_scapy.mnbcSound()
            step_button.config(bg="gray40")
            time.sleep(0.1)
            wait_for_step()
            step_button.config(bg="gray90")
            pyslac.examples.ev_slac_scapy.attenProfile()
            step_button.config(bg="gray40")
            time.sleep(0.1)
            wait_for_step()
            step_button.config(bg="gray90")
            pyslac.examples.ev_slac_scapy.mnbcSound()
            step_button.config(bg="gray40")
            time.sleep(0.1)
            wait_for_step()
            step_button.config(bg="gray90")
            pyslac.examples.ev_slac_scapy.attenProfile()
            step_button.config(bg="gray40")
            time.sleep(0.1)
            wait_for_step()
            step_button.config(bg="gray90")
            pyslac.examples.ev_slac_scapy.attenCharResponse()
            step_button.config(bg="gray40")
            time.sleep(0.2)
            wait_for_step()
            step_button.config(bg="gray90")
            pyslac.examples.ev_slac_scapy.ecdhExchange()
            step_button.config(bg="gray40")
            time.sleep(0.2)
            wait_for_step()
            step_button.config(bg="gray90")
            pyslac.examples.ev_slac_scapy.slacMatch()
        except Exception as e:
            error_found = True
            messagebox.showerror("Error", str(e))

    update_step_label()
    threading.Thread(target=se_slac_wrapper, daemon=True).start()
    threading.Thread(target=ev_slac_wrapper, daemon=True).start()


# Tkinter Setup
root = tk.Tk()
root.title("SLAC Stepper GUI")
root.geometry("700x600")

canvas = tk.Canvas(root, width=600, height=400, bg='white')
canvas.pack(side=tk.TOP, fill=tk.X)

ev_box = canvas.create_rectangle(100, 150, 200, 200, fill='lightblue')
canvas.create_text(150, 175, text="EV")

se_box = canvas.create_rectangle(500, 150, 600, 200, fill='lightgreen')
canvas.create_text(550, 175, text="SE")

canvas.create_line(200, 30, 200, 320, dash=(4, 4))
canvas.create_line(500, 30, 500, 320, dash=(4, 4))

# Control panel
control_frame = tk.Frame(root)
control_frame.pack(pady=10)

step_label = tk.Label(control_frame, text="Next Step: -")
step_label.pack()


def update_step_label():
    step_label.config(text=f"Next Step: {steps[next_step][3:] if next_step < len(steps) else 'Finished'}")  # noqa: E501


def start_slac_button():
    threading.Thread(target=start_slac, daemon=True).start()


def step_forward():
    step_event.set()


def toggle_run_all():
    if auto_run.is_set():
        auto_run.clear()
        runall_button.config(text="Run All")
    else:
        auto_run.set()
        runall_button.config(text="Pause Run All")
        step_event.set()


start_button = tk.Button(control_frame, bg="gray90", text="Start SLAC", command=start_slac_button)  # noqa: E501
start_button.pack(side=tk.LEFT, padx=5)

step_button = tk.Button(control_frame, bg="gray90", text="Step", command=step_forward)
step_button.pack(side=tk.LEFT, padx=5)

runall_button = tk.Button(control_frame, bg="gray90", text="Run All", command=toggle_run_all)  # noqa: E501
runall_button.pack(side=tk.LEFT, padx=5)


# Paned Window for consoles
paned = tk.PanedWindow(root, orient=tk.HORIZONTAL)
paned.pack(fill=tk.BOTH, expand=True)


# SE console
frame1 = tk.Frame(paned)
tk.Label(frame1, text="Console Output").pack()
se_console = scrolledtext.ScrolledText(frame1, state='disabled', width=60, height=20, bg='black', fg='white')  # noqa: E501
se_console.pack(fill=tk.BOTH)

paned.add(frame1)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
se_formatter = logging.Formatter('[SE] %(levelname)s - %(message)s')
ev_formatter = logging.Formatter('[EV] %(levelname)s - %(message)s')
se_handler = SELogHandler(se_console)
se_handler.setFormatter(se_formatter)
ev_handler = EVLogHandler(se_console)
ev_handler.setFormatter(ev_formatter)
logger.addHandler(se_handler)
logger.addHandler(ev_handler)


# Final window sizing
root.update()
root.minsize(root.winfo_width(), root.winfo_height())

# Run the app
root.mainloop()
