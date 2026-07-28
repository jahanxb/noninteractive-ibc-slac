# IBE-SLAC: Non-Interactive Identity-Based Key Establishment for ISO 15118-3 SLAC


This repository implements a non-interactive Identity-Based Cryptography (IBC) key establishment scheme integrated into the ISO 15118-3 SLAC protocol for EV charging security. It replaces the plaintext NMK transmission (standard SLAC) and the interactive ECDH exchange with an identity-based key derivation using bilinear pairings. Both sides compute the session key locally from their MAC-based identities and 
pre-distributed private keys. No additional protocol frames are transmitted over the PLC wire during key establishment.

This work is built on top of [dylanc1/pyslac (dh-based branch)](https://github.com/dylanc1/pyslac/tree/dh-based), which itself is a fork of [EcoG-io/pyslac](https://github.com/EcoG-io/pyslac).

---

## Table of Contents

1. [Background](#background)
2. [New Integration](#New-Integration)
3. [Hardware Requirements](#hardware-requirements)
4. [Physical Connection](#physical-connection)
5. [Host PC Network Configuration](#host-pc-network-configuration)
6. [Software Installation](#software-installation)
7. [Configuration](#configuration)
8. [Running the Protocol](#running-the-protocol)
9. [Using the GUI](#using-the-gui)
10. [Wireshark Packet Capture](#wireshark-packet-capture)
11. [Expected Results](#expected-results)
12. [Troubleshooting](#troubleshooting)
13. [Repository Structure](#repository-structure)
14. [Protocol Comparison](#protocol-comparison)
15. [References](#references)

---

## Background

The SLAC (Signal Level Attenuation Characterization) protocol, defined in ISO 15118-3, establishes a logical PLC network between an electric vehicle (PEV) and its charging station (EVSE) before charging begins. The two sides must agree on a shared Network Membership Key (NMK), a 16-byte AES-128 key that encrypts all subsequent PLC traffic.

**Standard SLAC vulnerability:** The NMK is transmitted in plaintext inside `CM_SLAC_MATCH.CNF`. Any passive attacker with a PLC sniffer can capture this frame and decrypt all PLC communication.

**ECDH extension:** Replaces plaintext NMK with an ECDH key exchange. Two additional frames (`CM_ECDH_EXCHANGE.REQ` and `CM_ECDH_EXCHANGE.RSP`) carry EC public keys. While the NMK is no longer transmitted in plaintext, the EC public keys are observable by any node on the PLC network, and the exchange is unauthenticated.

**This work (IBC):** Replaces the interactive ECDH exchange entirely. Both PEV and EVSE independently compute the same NMK using bilinear pairings and identity strings derived from MAC addresses. No additional frames are sent. The protocol frame count is identical to standard SLAC (8 frames). No cryptographic material appears in any transmitted frame.

---

## New Integration

Starting from `dh-based` branch, the following changes were made:

- Removed the `CM_ECDH_EXCHANGE` interactive key exchange entirely
- Added `pyslac/ibe_key_establishment.py`: Boneh-Franklin IBE over the SS512 pairing group using Charm-Crypto
- Modified `pyslac/session.py`: added `cm_ibe_key_establishment()` method called after `cm_atten_char()` and before `cm_slac_match()`
- Modified `pyslac/examples/ev_slac_scapy.py`: added `ibeKeyEstablishment()` function on the PEV side
- Added `slac_gui.py`: a tkinter-based GUI for running the full demo workflow
- Added `homeplug_slac.lua`: a Wireshark Lua dissector for annotated frame decoding

The NMK field in `CM_SLAC_MATCH.CNF` is set to a random 16-byte value. The IBE-derived NMK is computed locally on both sides and never transmitted.

---

## Hardware Requirements

You need exactly two devolo dLAN Green PHY Eval Board II devices and a Linux host PC.

| Component | Details |
|---|---|
| PEV Board (Board 1) | devolo dLAN Green PHY Eval Board II |
| EVSE Board (Board 2) | devolo dLAN Green PHY Eval Board II |
| PLC Modem | Qualcomm QCA7000 (on both boards) |
| Microcontroller | NXP LPC1758 ARM Cortex-M3 (on both boards) |
| Firmware version | FW v1.1.0-02 on both boards |
| Host OS | Ubuntu 24, Linux 6.x kernel |
| Host Python | 3.7 or higher (tested on 3.14) |
| Root access | Required — SLAC uses raw Layer 2 sockets |

The boards in the reference setup have the following addresses. You will need to replace these with your own board MAC addresses throughout the configuration.

| Role | MAC Address | IP Address |
|---|---|---|
| PEV (Board 1) | 88:FC:A6:1C:81:C2 | 192.168.0.11 |
| EVSE (Board 2) | 88:FC:A6:1C:81:BB | 192.168.0.12 |

---

## Physical Connection

### Figure: Hardware Setup

![Hardware Setup](figures/1000083211.jpg)

*Two devolo dLAN Green PHY Eval Board II devices. PEV board on the left, EVSE board on the right. Twisted-pair PLC cable connected between J3 screw terminals on both boards.*

### Power

Both boards are powered via Micro-USB cables connected to USB ports on the host PC. No external power supply is required.

### Ethernet

**Board 1 (PEV):** Connect the RJ45/J2 Ethernet port directly to the host PC's built-in Ethernet interface (`eno1` in the reference setup).

**Board 2 (EVSE):** Connect the RJ45/J2 Ethernet port to a second host interface (`enxa0cec837bab6` in the reference setup, a USB-C Ethernet dongle). This link is used to query the EVSE board directly with `plctool`.

**Important — which interface each process uses.** Both Python processes (`single_slac_session.py` and `ev_slac_scapy.py`) run on the **same** interface, `eno1`. They exchange SLAC frames with each other over that one segment using raw Layer 2 sockets.

This is not an oversight, and configuring the EVSE process onto the dongle will not work. `pyslac/session.py` hardcodes the EVSE board's own MAC (`88:FC:A6:1C:81:BB`) as the Ethernet source address of every frame it sends. A QCA7000 silently discards any frame whose source MAC equals its own address, so pointing the EVSE process at the dongle makes the EVSE board ignore `CM_SET_KEY.REQ` entirely and the session aborts with `SetKey Timeout raised`.

A consequence worth stating plainly for anyone reproducing this work: because both endpoints sit on one Ethernet segment, **the SLAC frames do not traverse the powerline.** The PLC link is established and verifiable, but the protocol exchange itself is host-local. This setup demonstrates the protocol logic and the identity-based key agreement; it is not a measurement of SLAC over PLC.


### PLC Wire (J3 Screw Terminals)

Connect the two boards using two copper wires screwed into the J3 screw terminal blocks on each board:

```
Board 1 J3 Pin 1 (PLC+) ---- wire ---- Board 2 J3 Pin 1 (PLC+)
Board 1 J3 Pin 2 (PLC-)  ---- wire ---- Board 2 J3 Pin 2 (PLC-)
```

Use a small flathead screwdriver to open and tighten the terminal screws. Any thin copper wire works.

### Initial Board Pairing

After connecting the J3 wire:

1. Press the PAIR button on Board 1 (PEV)
2. Within 60 seconds press the PAIR button on Board 2 (EVSE)
3. The PLC LED on both boards will go solid green when pairing succeeds

Verify the PLC link speed after pairing:

```bash
sudo plctool -i eno1 -m 88:FC:A6:1C:81:C2
```

Expected output includes `AvgPHYDR_TX = 009 mbps`.

---

## Host PC Network Configuration

The reference host PC has two network interfaces:

| Interface | Connection | Used by |
|---|---|---|
| `eno1` | Built-in Ethernet, connected directly to Board 1 (PEV) | **both** Python processes, and `plctool` queries of the PEV board |
| `enxa0cec837bab6` | USB-C Ethernet dongle, connected directly to Board 2 (EVSE) | `plctool` queries of the EVSE board only |

Your interface name will differ. Find it with `ip link` and use it wherever `eno1` appears in commands and configuration files.

Both interfaces must show a carrier before you start. Verify with:

```bash
ip -br link show          # both should read UP
cat /sys/class/net/eno1/carrier   # expect 1
```

Verify both boards are reachable:

```bash
ping 192.168.0.11   # PEV board
ping 192.168.0.12   # EVSE board
```

Query board hardware directly using plctool:

```bash
sudo plctool -i eno1 -I 88:FC:A6:1C:81:C2
sudo plctool -i enxa0cec837bab6 -I 88:FC:A6:1C:81:BB
```

---

## Software Installation

### Step 1: Install PBC Library (required for Charm-Crypto)

Charm-Crypto needs the PBC (Pairing-Based Cryptography) library built from source.

```bash
sudo apt install libgmp-dev flex bison
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar xzf pbc-0.5.14.tar.gz
cd pbc-0.5.14
./configure
make
sudo make install
sudo ldconfig
```

### Step 2: Install Charm-Crypto

```bash
git clone https://github.com/JHUISI/charm.git
cd charm
pip install .
```

If that fails, try:

```bash
pip install charm-crypto
```

### Step 3: Clone this repository

```bash
git clone https://github.com/jahanxb/noninteractive-ibc-slac.git
cd noninteractive-ibc-slac
```

### Step 4: Set up a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install scapy
```

### Step 5: Fix marshmallow version conflict (Python 3.14)

```bash
sudo pip install "marshmallow>=3.0.0,<4.0.0" "environs==9.5.0" --break-system-packages
```

### Step 6: Install the pyslac package

```bash
sudo pip install -e . --break-system-packages --ignore-installed cryptography
```

### Step 7: Verify installation

```bash
sudo python -c "import pyslac; print(pyslac.__file__)"
```

Expected output:

```
/path/to/ibe-slac/pyslac/__init__.py
```

---

## Configuration

### Network Interface and Board MAC Addresses

Open `pyslac/examples/cs_configuration.json` and set your interface name. **This must be the interface wired to the PEV board, and it must match `IFACE` in `ev_slac_scapy.py` exactly** — the two processes have to share one segment to hear each other. Setting this to the EVSE board's interface is the single most common way to break the demo:

```json
{
  "number_of_evses": 1,
  "parameters": [
    {
      "evse_id": "DE*SWT*E123456789",
      "network_interface": "eno1"
    }
  ]
}
```

Open `pyslac/examples/ev_slac_scapy.py` and set your board MAC addresses and interface:

```python
PEV_MAC  = "XX:XX:XX:XX:XX:XX"   # MAC address of your PEV board
EVSE_MAC = "XX:XX:XX:XX:XX:XX"   # MAC address of your EVSE board
IFACE    = "eno1"            # Your Ethernet interface name
```

Open `pyslac/session.py` and set the EVSE board MAC:

```python
host_mac = "XX:XX:XX:XX:XX:XX"   # MAC address of your EVSE board
```

Open `slac_gui.py` and update these constants at the top:

```python
IFACE      = "eno1"            # Your interface name
BOARD_PEV  = "XX:XX:XX:XX:XX:XX"   # PEV board MAC
BOARD_EVSE = "XX:XX:XX:XX:XX:XX"   # EVSE board MAC
```

### Environment Settings

Create or edit `.env` in the project root:

```
SLAC_INIT_TIMEOUT=10000
LOG_LEVEL=DEBUG
```

---

## Running the Protocol

**You do not need to reset the boards between runs.** The demo has been verified over repeated consecutive runs with the PLC link intact throughout — same NID, same 9 Mbps, station count never dropping. Reset only for initial pairing, or if `plctool -m` shows the boards are no longer on a shared network.

**Never delete `ibe_master_secret.bin` or `ibe_generator.bin`.** See Step 1.

### Step 1: One-Time Setup — Generate IBE Keys and Pair the Boards

The IBE master secret and generator are long-lived Private Key Generator material, equivalent to a CA key. Both the PEV and the EVSE must read the **same** files — that shared material is precisely what allows each side to derive the session key locally with nothing sent over the wire.

Generate them **once**, with both processes stopped:

```bash
cd /home/jack/projects/noninteractive-ibc-slac
venv/bin/python pyslac/ibe_key_establishment.py
# prints matching EV and EVSE NMKs, and writes the two .bin files
```

> **Do not delete these files before a run.** If they are missing, both processes start within seconds of each other, both find no key material, and both generate a *different* random master secret — so the two sides derive different NMKs and key agreement fails. Deleting them is the most reliable way to break this demo, not to fix it.

Pair the boards only if they are not already on a shared PLC network:

```bash
sudo plctool -i enxa0cec837bab6 -T 88:FC:A6:1C:81:BB   # EVSE MAC — factory reset
sudo plctool -i eno1            -T 88:FC:A6:1C:81:C2   # PEV MAC  — factory reset
# wait 60 seconds for the boards to auto-pair, then verify:
sudo plctool -i eno1 -m 88:FC:A6:1C:81:C2
```

A healthy link reports `STATIONS = 1` and `AvgPHYDR_TX = 009 mbps` on both boards, with the same `NID` on each. This check is read-only and safe to repeat any time.

### Step 2: Start EVSE (Terminal 1)

```bash
cd /home/jack/projects/noninteractive-ibc-slac
sudo venv/bin/python -u pyslac/examples/single_slac_session.py
```

The `cd` matters. The scripts locate `cs_configuration.json` relative to themselves, but the virtual environment and the IBE key files are per-directory — running from a different copy of the project is a common and confusing failure.

### Step 3: Start EV (Terminal 2), within 30 seconds

```bash
cd /home/jack/projects/noninteractive-ibc-slac
sudo venv/bin/python -u pyslac/examples/ev_slac_scapy.py
```

**Timing is the one thing to get right.** Start the EV within roughly 30 seconds of the EVSE. The EVSE's matching window opens about 30 s after launch and closes about 92 s in, while the EV itself waits `SLAC_SETTLE_TIME` (30 s) before sending its first frame. Starting the EV too late means its first frame arrives after the window has closed, which looks like a protocol failure but is only a timing miss. Anywhere in the first 30 seconds is comfortable.

The full handshake then runs automatically. Both terminals display the IBE key establishment details and the derived NMK. Verify that the NMK printed on both sides is identical.

The terminal output samples are given in folder output_samples/single_slac_session.txt and slac_scapy.txt

![Terminal Demo](figures/command_line_single_slac.png)
---

## Using the GUI

The GUI automates the full workflow and provides an animated sequence diagram showing each SLAC step as it executes.

```bash
sudo python slac_gui.py
```

**Panel 1 — Board Reset:** ⚠️ **Do not use this for a normal demo.** "Reset Boards" factory resets both QCA7000 boards *and deletes the IBE key files*. The deletion causes the two processes to generate different master secrets, so key agreement fails on the next run (see "NMK values differ" in Troubleshooting). Use it only for initial pairing, and regenerate the key files afterwards with `venv/bin/python pyslac/ibe_key_establishment.py`.

For a normal demo, go straight to Panel 2. The Run path is entirely independent of Reset and leaves the boards' pairing untouched.

**Panel 2 — Run SLAC+IBE:** Click "Start Session". The GUI starts the EVSE process, waits 15 seconds for chip initialization, then starts the EV process. The sequence diagram on the left animates each protocol step as it is logged. The IBE step shows a highlighted box labelled "IBE — NO WIRE TRAFFIC" between the attenuation and match steps.

**Console tabs:** Three tabs (EVSE, PEV, Reset) show the full output from each process in real time.

### Figure: GUI Demo

![GUI Demo](figures/gui_interface.png)


![Session GIF](output_samples/demo1.gif)


---

## Wireshark Packet Capture
#### Not mandatory but for better packet exploration, you can use this plugin. 
### Install the Custom Lua Dissector

```bash
sudo cp homeplug_slac.lua /usr/lib/x86_64-linux-gnu/wireshark/plugins/
```

Reload plugins in Wireshark with `Ctrl+Shift+L`.

### Capture Filter

To capture only HomePlug AV SLAC frames:

```
eth.type == 0x88e1
```

### Capture to File

```bash
sudo tshark -i eno1 -f "ether proto 0x88e1" -w capture.pcap
```

The dissector labels each frame with its SLAC step, direction, and a description of what it carries. For `CM_SLAC_MATCH.CNF` it shows the NMK field with a note explaining that the real NMK is never transmitted.

### Figure: Wireshark Capture

![Wireshark Capture](output_samples/wireshark.png)

*Wireshark capture of a complete IBE-SLAC session. 8 frames total. CM_SLAC_MATCH.CNF frame shows NMK field confirming no key material was transmitted over the wire.*


---

## Expected Results

### Terminal Output

After a successful run you should see the following on both terminals. The NMK values must be identical.

**EVSE terminal:**

```
CM_SET_KEY: Finished!
[STEP 1]  SLAC PARAMETER EXCHANGE + IDENTITY DISCOVERY
  EV   ID : EV:88fca61c81c2
  EVSE ID : EVSE:88fca61c81bb

[STEP 5]  IBE KEY ESTABLISHMENT  (EVSE Side)
  NMK     : 578e4650bedb6d9e0164b6abc55d89de  (16 bytes)
  NID     : 44adefa9e2d30e  (7 bytes)

[STEP 6]  SLAC MATCH - HANDSHAKE COMPLETE
  Result  : PEV-EVSE MATCHED

PEV-EVSE MATCHED Successfully, Link Established
```

**EV terminal:**

```
[STEP 6]  IBE KEY ESTABLISHMENT  (PEV Side)
  NMK     : 578e4650bedb6d9e0164b6abc55d89de  (16 bytes)
  NID     : 44adefa9e2d30e  (7 bytes)

SLAC + IBE HANDSHAKE COMPLETE
  NMK Match : Both EV and EVSE derived same NMK independently

PEV-EVSE MATCHED Successfully!
```

### A Retried `CM_SLAC_PARM.REQ` Is Normal

You will routinely see this in the EV terminal, and it is **not** a failure:

```
Waiting for CM_SLAC_PARM.CNF... (attempt 1/5)
Timeout waiting for mm_type 0x6065
Waiting for CM_SLAC_PARM.CNF... (attempt 2/5)
```

On entering `CM_SLAC_PARM` the EVSE closes and reopens its raw socket (`reset_socket()`). Both sides come out of their 30-second settle at almost the same instant — measured at 19 ms apart — so the EV's first `CM_SLAC_PARM.REQ` reliably lands in that reopen window and is dropped. The EV now retransmits, and attempt 2 succeeds. ISO 15118-3 expects this frame to be retransmitted in any case.

Only treat it as a fault if all five attempts are exhausted.

### The Derived NMK Is Deterministic

For a fixed pair of board MAC addresses and a fixed master secret, the derived NMK is **the same on every run**. In the reference setup it is always:

```
NMK = 00890bf2acfaac9f7be8b63d5666cc53
NID = d79841200e4807
```

This is not caching. `derive_nmk()` is called with `run_id = bytes(8)`, a hardcoded all-zero value, and the `run_id` field is likewise left at zero in `CM_SLAC_PARM.REQ` — which is why the EVSE logs `Run ID: b'\x00\x00\x00\x00\x00\x00\x00\x00'`. The NMK itself is not all zeros; it is a normal pseudorandom SHA-256 output whose leading byte happens to be `00`.

**Security implication, stated explicitly.** Because the run ID never varies, there is no per-session key freshness: every charging session between the same two boards reuses one static NMK. Anyone who recovers that key once — via a compromised board, an extracted identity private key, or a side channel — can decrypt every past and future session between that pair. The claim that no key material appears on the wire remains true; the claim of a fresh session key does not. The derivation itself is sound and separates keys correctly on both identity and run ID:

| Varied input | Derived NMK |
|---|---|
| `run_id = 0000000000000000` | `00890bf2acfaac9f7be8b63d5666cc53` |
| `run_id = 0000000000000001` | `bd70214091d52904fa167b700d33f99d` |
| `run_id = a1b2c3d4e5f60718` | `6ce5479b6d5ecbf1d46f3ba232f6eca2` |
| different EV identity | `33891e2c6afc2092dade9e79f5cbb75b` |
| different EVSE identity | `684b9357f15ca39e59ba30f33ce859f6` |

To obtain genuine session freshness, have the EV generate a random 8-byte `run_id` into `CM_SLAC_PARM.REQ` — the purpose ISO 15118-3 defines for that field — and pass the received value into `derive_nmk()` on both sides in place of `bytes(8)`. Both sides already carry it; the EVSE parses and logs it today.

### Protocol Frame Count

| Protocol | Total Frames | Extra Key Frames | Key Material on Wire |
|---|---|---|---|
| Original SLAC (ISO 15118-3) | 8 | 0 — NMK in plaintext | NMK plaintext |
| SLAC + ECDH  | 10 | +2 frames | EC public keys visible |
| SLAC + IBC (this work) | 8 | 0 | None |

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'pyslac'`**

Run with the virtual environment Python explicitly:
```bash
sudo venv/bin/python pyslac/examples/single_slac_session.py
```

**`ModuleNotFoundError: No module named 'charm'`**

Charm-Crypto is not installed in the environment being used by sudo. Install it system-wide:
```bash
sudo pip install charm-crypto --break-system-packages
```

**`AttributeError: module 'marshmallow' has no attribute '__version_info__'`**

Downgrade marshmallow to a 3.x version:
```bash
sudo pip install "marshmallow>=3.0.0,<4.0.0" --break-system-packages --force-reinstall
```

**`OSError: There is no such interface`**

The interface name in `cs_configuration.json` or `ev_slac_scapy.py` does not match your system. Run `ip link` to find the correct name.

**EVSE times out waiting for `CM_SLAC_PARM.REQ`, or EV reports `No CM_SLAC_PARM.CNF - aborting`**

Check these in order:

1. **Interface mismatch.** `network_interface` in `cs_configuration.json` must equal `IFACE` in `ev_slac_scapy.py`. If the EVSE is pointed at the EVSE board's interface, it cannot hear the EV at all. This is the most frequent cause.
2. **Timing.** The EV must be started within ~30 s of the EVSE. Later than that and the matching window has already closed.
3. **All 5 retry attempts exhausted.** A single dropped attempt is normal (see "A Retried `CM_SLAC_PARM.REQ` Is Normal"). Five failures means the EVSE is not listening on the same segment.

A single `Timeout waiting for mm_type 0x6065` followed by `attempt 2/5` is expected behaviour and needs no action.

**`SetKey Timeout raised` — PLC chip initialization failed**

The EVSE process is on an interface wired to a board whose MAC equals the source address hardcoded in `session.py` (`88:FC:A6:1C:81:BB`). A QCA7000 discards frames that appear to originate from itself, so it never answers `CM_SET_KEY.REQ`. Point `network_interface` in `cs_configuration.json` back at the PEV board's interface (`eno1`).

You can confirm a board is alive and which source addresses it will answer without changing any board state:

```bash
sudo plctool -i eno1 -I 88:FC:A6:1C:81:C2            # PEV board identity
sudo plctool -i enxa0cec837bab6 -I 88:FC:A6:1C:81:BB # EVSE board identity
```

**PLC LED blinking slowly / link lost**

Slow blinking means the boards are not on a shared powerline network. Confirm with `plctool -m` on both boards: a healthy link shows the same `NID` on each, `STATIONS = 1`, and `AvgPHYDR_TX = 009 mbps`. If either board reports `Found 0 Network(s)` or `STATIONS = 0`, re-pair using the reset procedure in Step 1.

Note that in the working configuration a normal run does **not** drop the pairing, because the EVSE's `CM_SET_KEY.REQ` is ignored by the board it is addressed to. If the LEDs go slow-blink after a run, the interface configuration has probably been changed.

**Edits to `pyslac/*.py` appear to have no effect**

The virtual environment may contain a second copy of the package that shadows your working tree. Running a script from `pyslac/examples/` puts that directory on `sys.path`, not the repository root, so `import pyslac` resolves through site-packages. Check where it actually resolves:

```bash
cat venv/lib/python3.*/site-packages/pyslac.pth
```

It must contain the repository root. If it points somewhere else (for example `venv/src/pyslac`), that stale copy is what runs. A give-away is a traceback citing file paths that no longer exist in your tree. Fix by writing the repository root into that `.pth` file, and delete the stale checkout so it cannot shadow again.

**`error: uninstall-no-record-file for cryptography`**

```bash
sudo pip install -e . --break-system-packages --ignore-installed cryptography
```

**NMK values differ between EV and EVSE**

The two sides are reading different master secrets. The usual cause is that `ibe_master_secret.bin` and `ibe_generator.bin` were **deleted** before the run: both processes then start seconds apart, both find no key material, and each generates its own random master secret.

Do not delete these files. Regenerate them once, with both processes stopped, and leave them in place:

```bash
venv/bin/python pyslac/ibe_key_establishment.py
# prints matching EV and EVSE NMKs plus "Match: True"
```

Also confirm both sides resolve the same key files — `pyslac/ibe_key_establishment.py` holds absolute paths in its constructor defaults, and a stale copy of the package (see above) will point at a different location or one that no longer exists.

---

## Repository Structure

```
ibe-slac/
    pyslac/
        examples/
            single_slac_session.py      EVSE side entry point
            ev_slac_scapy.py            EV simulator with IBC
            cs_configuration.json       Interface and EVSE ID config
        session.py                      EVSE SLAC session with IBC integration
        ibe_key_establishment.py        Boneh-Franklin IBE over SS512
        environment.py                  Environment variable handling
        enums.py                        SLAC message type definitions
        sockets/
            async_linux_socket.py       Raw socket implementation
    slac_gui.py                         Demo GUI
    homeplug_slac.lua                   Wireshark Lua dissector
    Figures/
        Hardware_setup.jpg              Hardware photo
        SLAC_protocol.png               Protocol sequence diagram
        SLAC_MATCH.png                  Wireshark capture screenshot
        gui_demo.png                    GUI screenshot
        session_demo.gif                Full session demo GIF
    .env                                Environment settings
    requirements.txt                    Python dependencies
    README.md                           This file
```

---

## Protocol Comparison

The full SLAC + IBC frame sequence:

| Step | Frame | Direction | Description |
|---|---|---|---|
| 1 | CM_SLAC_PARM.REQ | PEV → Broadcast | EV announces presence. EVSE learns PEV MAC, becomes IBE identity. |
| 2 | CM_SLAC_PARM.CNF | EVSE → PEV | EVSE confirms. PEV learns EVSE MAC, becomes IBE identity. |
| 3 | CM_START_ATTEN_CHAR.IND | PEV → Broadcast | EV initiates attenuation measurement. |
| 4 | CM_MNBC_SOUND.IND | PEV → Broadcast | Sound bursts for PLC attenuation measurement. |
| 5 | CM_ATTEN_CHAR.IND | EVSE → PEV | EVSE sends averaged attenuation profile. |
| 6 | CM_ATTEN_CHAR.RSP | PEV → EVSE | EV acknowledges. Both sides begin IBC locally. |
|   | IBC Key Establishment | LOCAL | Both sides compute bilinear pairing independently. Zero frames sent. |
| 7 | CM_SLAC_MATCH.REQ | PEV → EVSE | EV requests final SLAC matching. |
| 8 | CM_SLAC_MATCH.CNF | EVSE → PEV | EVSE confirms. Session established. |

---

## References

- ISO 15118-3: Vehicle to Grid Communication Interface — Physical and Data Link Layer Requirements
- Boneh, D. and Franklin, M., Identity-Based Encryption from the Weil Pairing, CRYPTO 2001
- Baker, R. and Martinovic, I., Losing the Car Keys: Wireless PHY-Layer Insecurity in EV Charging, USENIX Security 2019
- EcoG-io/pyslac: https://github.com/EcoG-io/pyslac
- dylanc1/pyslac dh-based branch: https://github.com/dylanc1/pyslac/tree/dh-based
- Charm-Crypto: https://github.com/JHUISI/charm
- Qualcomm open-plc-utils (plctool): https://github.com/qca/open-plc-utils
- HomePlug Green PHY Specification Release Version 1.1
- devolo dLAN Green PHY Eval Board II Data Sheet v1.00