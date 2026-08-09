#!/usr/bin/env python3
"""
Test script to capture GUI crash details
Run with: sudo python test_gui_crash.py
"""

import sys
import traceback
import os

# Add project to path
sys.path.insert(0, '/home/jack/projects/noninteractive-ibc-slac')

print("="*70)
print("STARTING GUI WITH DETAILED ERROR CAPTURE")
print("="*70)
print()

try:
    print("[1/5] Importing tkinter...")
    import tkinter as tk
    print("  ✓ Tkinter imported")

    print("[2/5] Importing slac_gui module...")
    from pyslac.examples.slac_gui import SLACDemoApp
    print("  ✓ SLACDemoApp imported")

    print("[3/5] Creating root window...")
    root = tk.Tk()
    print("  ✓ Tk() created")

    print("[4/5] Creating SLACDemoApp instance...")
    app = SLACDemoApp(root)
    print("  ✓ SLACDemoApp instance created")

    print("[5/5] Starting main loop...")
    print()
    print("GUI running - watch for crash message below:")
    print("-"*70)

    root.mainloop()

    print("-"*70)
    print("GUI exited normally")

except Exception as e:
    print("-"*70)
    print("CRASH DETECTED!")
    print("="*70)
    print(f"\nException Type: {type(e).__name__}")
    print(f"Exception Message: {str(e)}")
    print("\nFull Stack Trace:")
    print("-"*70)
    traceback.print_exc()
    print("-"*70)
    print("\n⚠️  ERROR DETAILS CAPTURED ABOVE\n")
    sys.exit(1)

except KeyboardInterrupt:
    print("\nGUI interrupted by user (Ctrl+C)")
    sys.exit(0)

except SystemExit as e:
    if e.code != 0:
        print(f"\nGUI exited with code: {e.code}")
        sys.exit(e.code)
