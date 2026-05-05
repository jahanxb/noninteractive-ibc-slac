# devolo dLAN Green PHY PLC Communication Setup and Deployment Guide

## Overview

This document describes the complete setup, configuration, and deployment process for establishing Power Line Communication (PLC) between two devolo dLAN Green PHY evaluation boards using the SLAC (Signal Level Attenuation Characterization) protocol as defined in ISO 15118-3. Two implementations are covered: the standard pyslac implementation and a Diffie-Hellman enhanced version developed by Dylan (dylanc1).

---

## Hardware

### Devices

- Board 1: devolo dLAN Green PHY Eval Board II running PEV firmware (FW v1.1.0-02)
  - Role: Electric Vehicle (PEV) side
  - MAC Address: 88:FC:A6:1C:81:C2
  - IP Address: 192.168.0.11
  - Chip: Qualcomm QCA7000
  - MCU: NXP LPC1758 ARM Cortex-M3

- Board 2: devolo dLAN Green PHY Eval Board II running EVSE firmware (FW v1.1.0-02)
  - Role: Electric Vehicle Supply Equipment (EVSE / Charging Station) side
  - MAC Address: 88:FC:A6:1C:81:BB
  - IP Address: 192.168.0.12
  - Chip: Qualcomm QCA7000
  - MCU: NXP LPC1758 ARM Cortex-M3

### PLC Protocol

- Standard: HomePlug Green PHY / IEEE 1901
- Physical Link: Twisted pair wire connected between J3 screw terminals on both boards
- Encryption: AES-128 at MAC layer

---

## Physical Connection Setup

### Power

Both boards are powered via Micro-USB cables connected to USB ports on the host PC. No additional power supply is needed.

### Ethernet

Board 1 (PEV) Ethernet (RJ45/J2) is connected directly to the host PC's built-in Ethernet interface (enp0s31f6). Board 2 (EVSE) is reachable through the PLC link established over the J3 twisted pair wire.

### PLC Wire (J3 Twisted Pair)

The two boards are connected to each other via two copper wires screwed into the J3 screw terminal blocks on each board:

    Board1 J3 Pin1 (PLC+) ---- wire ---- Board2 J3 Pin1 (PLC+)
    Board1 J3 Pin2 (PLC-)  ---- wire ---- Board2 J3 Pin2 (PLC-)

A small flathead screwdriver or flat tool is used to loosen and tighten the screw terminals. Any thin copper wire works for this connection.

### Board Pairing

After connecting the J3 wire, press the PAIR button on Board 1 (PEV), then within 60 seconds press the PAIR button on Board 2 (EVSE). The PLC LED on both boards will go solid green to indicate a successful pairing.

---

## Host PC Network Configuration

### Network Interfaces

The host PC has two network interfaces:

    enp0s31f6     -- built-in Ethernet, connected directly to Board1 (PEV)
    enxa0cec837bab6 -- USB-C Ethernet dongle, connected to university internet

### Board IP Discovery

The boards run their own internal network stack and assign themselves fixed IPs. The host PC does not need a static IP on enp0s31f6 to reach the boards. To verify the boards are reachable:

    ping 192.168.0.11
    ping 192.168.0.12

### Hardware Query via plctool

The QCA7000 chip on each board can be queried directly using plctool:

    sudo plctool -i enp0s31f6 -I
    sudo plctool -i enp0s31f6 -I 88:FC:A6:1C:81:BB

This returns real hardware information including MAC address, manufacturer, firmware role, network key, and network ID directly from the board hardware.

---

## Project Directory Structure

All projects reside under:

    /opt/VehicleSecProject/

The directory contains two separate deployments:

    /opt/VehicleSecProject/
        slac_plain/
            pyslac/         -- Standard pyslac (EcoG-io/pyslac, v0.8.3)
        slac_dylan_ddh/
            pyslac/         -- Dylan's dh-based pyslac fork (dylanc1/pyslac, dh-based branch)

---

## Project 1: Standard pyslac

### Source

Repository: https://github.com/EcoG-io/pyslac
Location on disk: /opt/VehicleSecProject/slac_plain/pyslac

### Description

This implements the standard SLAC protocol as defined in ISO 15118-3. It handles the full PEV-EVSE association process including parameter exchange, attenuation characterization, and SLAC matching. The NMK (Network Membership Key) used for AES-128 encryption of the PLC link is randomly generated and delivered to the PEV inside the CM_SLAC_MATCH message.

### Directory Layout

    /opt/VehicleSecProject/slac_plain/pyslac/
        pyslac/
            examples/
                single_slac_session.py      -- EVSE side entry point
                multiple_slac_sessions.py   -- multi-EVSE entry point
                ev_slac_scapy.py            -- PEV simulator using scapy
                cs_configuration.json       -- interface and EVSE ID config
            session.py                      -- core SLAC session logic
            environment.py                  -- environment variable handling
            enums.py                        -- SLAC message type definitions
            sockets/
                async_linux_socket.py       -- raw socket implementation
        .env                                -- environment settings
        .env.dev.local                      -- template for local settings
        Makefile                            -- run targets
        pyproject.toml                      -- project dependencies
        poetry.lock                         -- locked dependency versions

### Installation

Step 1 - Install Poetry:

    curl -sSL https://install.python-poetry.org | python3 -
    export PATH="$HOME/.local/bin:$PATH"

Step 2 - Fix marshmallow version conflict (Python 3.14 compatibility):

    sudo pip install "marshmallow>=3.0.0,<4.0.0" "environs==9.5.0" --break-system-packages

Step 3 - Install pyslac into system Python:

    cd /opt/VehicleSecProject/slac_plain/pyslac
    sudo pip install -e . --break-system-packages --ignore-installed cryptography

Step 4 - Verify installation:

    sudo python -c "import pyslac; print(pyslac.__file__)"
    # Expected: /opt/VehicleSecProject/slac_plain/pyslac/pyslac/__init__.py

### Configuration

The interface and EVSE ID are configured in:

    /opt/VehicleSecProject/slac_plain/pyslac/pyslac/examples/cs_configuration.json

Contents:

    {
      "number_of_evses": 1,
      "parameters": [
        {
          "evse_id": "DE*SWT*E123456789",
          "network_interface": "enp0s31f6"
        }
      ]
    }

The environment settings are in:

    /opt/VehicleSecProject/slac_plain/pyslac/.env

Contents:

    SLAC_INIT_TIMEOUT=1000
    LOG_LEVEL="DEBUG"

### Running

Open two terminals. Start the EVSE side first in Terminal 1:

    cd /opt/VehicleSecProject/slac_plain/pyslac
    make run-local-sudo-single

Wait until the output shows:

    DEBUG:slac_session:CM_SLAC_PARM: Started...

Then immediately start the PEV simulator in Terminal 2:

    cd /opt/VehicleSecProject/slac_plain/pyslac
    make run-ev-slac

### Expected Output

EVSE side (Terminal 1):

    INFO:slac_session: Starting PySlac version: 0.8.3
    INFO:slac_session:CM_SET_KEY: Started...
    DEBUG:slac_session:New NMK: b'529d0646839c7ba19868bc17454f8e23'
    INFO:slac_session:CM_SET_KEY: Finished!
    DEBUG:slac_session:CM_SLAC_PARM: Started...
    DEBUG:slac_session:Sent SLAC_PARM.CNF
    DEBUG:slac_session:CM_START_ATTEN_CHAR: Finished!
    DEBUG:slac_session:CM_MNBC_SOUND: Finished!
    DEBUG:slac_session:CM_ATTEN_CHAR: Finished!
    DEBUG:slac_session:CM_SLAC_MATCH: Finished!
    INFO:slac_session:PEV-EVSE MATCHED Successfully, Link Established

PEV side (Terminal 2):

    EV:Starting Setup
    EV:Finished Setup
    EV:Starting Key Confirmation
    EV:Sent Key Confirmation
    EV:Sending Param Request
    EV:Sent Param Request
    EV:Sending Attenuation Characterization Indication
    EV:Sending MNBC Sound Indication
    EV:Sending Attenuation Characterization Response
    EV:Starting Slac Match
    EV:Sending Slac Match Request

### SLAC Protocol Steps

    1. CM_SET_KEY         -- EVSE sets new random NMK into QCA7000 chip
    2. CM_SLAC_PARM       -- EVSE broadcasts SLAC parameters, PEV responds
    3. CM_START_ATTEN_CHAR -- signal attenuation characterization begins
    4. CM_MNBC_SOUND      -- PEV sends sound packets, EVSE measures attenuation
    5. CM_ATTEN_CHAR      -- attenuation results exchanged
    6. CM_SLAC_MATCH      -- NMK delivered to PEV, link established

---

## Project 2: Dylan's Diffie-Hellman Enhanced pyslac

### Source

Repository: https://github.com/dylanc1/pyslac (branch: dh-based)
Location on disk: /opt/VehicleSecProject/slac_dylan_ddh/pyslac

### Description

This is a fork of the standard pyslac that adds an ECDH (Elliptic Curve Diffie-Hellman) key exchange step between the attenuation characterization and the SLAC match. The key difference from standard SLAC is that the NMK is never transmitted over the wire in plaintext. Instead, both PEV and EVSE independently compute the same shared secret using their exchanged public keys. This prevents an attacker who captures the SLAC handshake from learning the NMK.

### How ECDH Improves Standard SLAC Security

Standard SLAC vulnerability:

    CM_SLAC_MATCH.CNF contains the NMK in plaintext
    An attacker capturing this frame learns the AES-128 key
    All subsequent PLC traffic can be decrypted

Dylan's dh-based improvement:

    ECDH public keys are exchanged in a new CM_ECDH_EXCHANGE message
    Both sides compute: shared_secret = their_private_key * peer_public_key
    NMK is derived from the shared secret
    NMK is never transmitted -- attacker cannot recover it from captured frames

### Directory Layout

    /opt/VehicleSecProject/slac_dylan_ddh/pyslac/
        pyslac/
            examples/
                single_slac_session.py      -- EVSE side entry point
                ev_slac_scapy.py            -- PEV simulator with ECDH support
                cs_configuration.json       -- interface and EVSE ID config
            session.py                      -- core SLAC session logic with ECDH
            environment.py                  -- environment variable handling
            enums.py                        -- SLAC message types including CM_ECDH_EXCHANGE
            sockets/
                async_linux_socket.py       -- raw socket implementation
        .env                                -- environment settings
        Makefile                            -- run targets
        pyproject.toml                      -- project dependencies

### Installation

Step 1 - Install dependencies (includes cryptography library for ECDH):

    cd /opt/VehicleSecProject/slac_dylan_ddh/pyslac
    sudo pip install -e . --break-system-packages --ignore-installed cryptography

Step 2 - Remove old pyslac from system if previously installed:

    sudo rm -rf /usr/local/lib/python3.14/dist-packages/pyslac*

Step 3 - Verify correct version is loaded:

    sudo python -c "import pyslac; print(pyslac.__file__)"
    # Expected: /opt/VehicleSecProject/slac_dylan_ddh/pyslac/pyslac/__init__.py

### Configuration

Same as standard pyslac. Edit the interface in:

    /opt/VehicleSecProject/slac_dylan_ddh/pyslac/pyslac/examples/cs_configuration.json

Contents:

    {
      "number_of_evses": 1,
      "parameters": [
        {
          "evse_id": "DE*SWT*E123456789",
          "network_interface": "enp0s31f6"
        }
      ]
    }

Environment settings in:

    /opt/VehicleSecProject/slac_dylan_ddh/pyslac/.env

Contents:

    SLAC_INIT_TIMEOUT=10000
    LOG_LEVEL="DEBUG"

Interface fixes applied to example files during setup:

    sed -i 's/eth0/enp0s31f6/g' pyslac/examples/single_slac_session.py
    sed -i 's/enp0s3"/enp0s31f6"/g' pyslac/examples/ev_slac_scapy.py

### Running

Because sudo does not inherit the Python path, both sides must be run with PYTHONPATH set explicitly.

Open two terminals. Start EVSE side first in Terminal 1:

    cd /opt/VehicleSecProject/slac_dylan_ddh/pyslac
    sudo PYTHONPATH=/opt/VehicleSecProject/slac_dylan_ddh/pyslac python pyslac/examples/single_slac_session.py

Wait until the output shows:

    DEBUG:slac_session:CM_SLAC_PARM: Started...

Then immediately start PEV simulator in Terminal 2:

    cd /opt/VehicleSecProject/slac_dylan_ddh/pyslac
    sudo PYTHONPATH=/opt/VehicleSecProject/slac_dylan_ddh/pyslac python pyslac/examples/ev_slac_scapy.py

### Expected Output

EVSE side (Terminal 1):

    INFO:slac_session: Starting PySlac version: 0.8.3
    INFO:slac_session:CM_SET_KEY: Started...
    DEBUG:slac_session:New NMK: b'603a5d44c3396609201fa397bdfb700c'
    INFO:slac_session:CM_SET_KEY: Finished!
    DEBUG:slac_session:CM_SLAC_PARM: Started...
    DEBUG:slac_session:Sent SLAC_PARM.CNF
    DEBUG:slac_session:CM_START_ATTEN_CHAR: Finished!
    DEBUG:slac_session:CM_MNBC_SOUND: Finished!
    DEBUG:slac_session:CM_ATTEN_CHAR: Finished!
    DEBUG:slac_session:CM_ECDH_EXCHANGE: Started...
    DEBUG:slac_session:Sent ECDH_EXCHANGE.REQ
    DEBUG:slac_session:New NMK Established!
    DEBUG:slac_session:New NMK: b'\xda\x85\xed\x0f\xe7\xe39\x98\x92\x99Ep^\xa0\x99\xb5'
    DEBUG:slac_session:CM_SLAC_MATCH: Finished!
    INFO:slac_session:PEV-EVSE MATCHED Successfully, Link Established

PEV side (Terminal 2):

    EV:Starting Setup
    EV:Finished Setup
    EV:Starting Key Confirmation
    EV:Sent Key Confirmation
    EV:Sending Param Request
    EV:Sent Param Request
    EV:Sending Attenuation Characterization Indication
    EV:Sending MNBC Sound Indication
    EV:Sending Attenuation Profile Indication
    EV:Sending Attenuation Characterization Response
    EV:Starting ECDH Exchange
    Public key: b'\x04\xc9\xc6\xae\xac\xc4\x9f\xba\xb3\x1cp\xd9\xa0\x18...'
    EV:Sending ECDH Exchange Response
    Sent ECDH Exchange frame
    EV:Starting Slac Match
    EV:Sending Slac Match Request

### SLAC with ECDH Protocol Steps

    1.  CM_SET_KEY           -- EVSE sets initial NMK into QCA7000 chip
    2.  CM_SLAC_PARM         -- EVSE broadcasts SLAC parameters, PEV responds
    3.  CM_START_ATTEN_CHAR  -- signal attenuation characterization begins
    4.  CM_MNBC_SOUND        -- PEV sends sound packets, EVSE measures attenuation
    5.  CM_ATTEN_CHAR        -- attenuation results exchanged
    6.  CM_ECDH_EXCHANGE     -- EVSE sends its ECDH public key to PEV
    7.  PEV sends its ECDH public key back to EVSE
    8.  Both sides independently compute the shared secret
    9.  New NMK is derived from the shared secret (never transmitted)
    10. CM_SLAC_MATCH        -- link established with DH-derived NMK

---

## PLC LED Behavior

During normal pairing (PAIR button press):
- PLC LED solid green -- boards are paired and PLC link is active

During pyslac execution:
- PLC LED goes off at start -- pyslac resets the NMK via CM_SET_KEY
- PLC LED may briefly light during SLAC matching
- PLC LED off at end -- session closes and network is left (Leaving Logical Network)

This is expected behavior. In a real EV charging scenario each session generates a fresh unique NMK. To restore the PLC LED after running pyslac, press the PAIR button on both boards again.

---

## System Requirements

    OS:           Linux (Ubuntu/Debian)
    Python:       3.7 or higher (tested on 3.14 with compatibility fixes)
    Root access:  Required (SLAC uses raw Layer 2 socket frames)
    Tools:        plctool, nmap, tcpdump, poetry

### Package Dependencies

Standard pyslac:

    environs==9.5.0
    marshmallow>=3.0.0,<4.0.0
    python-dotenv

Dylan's dh-based pyslac (additional):

    cryptography==44.0.0
    cffi>=1.12
    pycparser

---

## Common Issues and Fixes

Issue: ModuleNotFoundError: No module named 'pyslac'
Fix: Run with PYTHONPATH set explicitly:
    sudo PYTHONPATH=/opt/VehicleSecProject/slac_dylan_ddh/pyslac python pyslac/examples/single_slac_session.py

Issue: AttributeError: module 'marshmallow' has no attribute '__version_info__'
Fix: Downgrade marshmallow to 3.x:
    sudo pip install "marshmallow>=3.0.0,<4.0.0" --break-system-packages --force-reinstall

Issue: OSError: There is no such interface eth0
Fix: Update cs_configuration.json to use enp0s31f6 instead of eth0

Issue: ImportError: cannot import name 'CM_ECDH_EXCHANGE' from 'pyslac.enums'
Fix: Old pyslac installation is being loaded. Remove it:
    sudo rm -rf /usr/local/lib/python3.14/dist-packages/pyslac*

Issue: SLAC matching times out (Matching process task canceled)
Fix: Start the PEV simulator (Terminal 2) faster after the EVSE starts.
     Increase timeout in .env: SLAC_INIT_TIMEOUT=10000

Issue: error: uninstall-no-record-file for cryptography
Fix: Use --ignore-installed flag:
    sudo pip install -e . --break-system-packages --ignore-installed cryptography

---

## Quick Reference Commands

Check boards are reachable:

    ping 192.168.0.11
    ping 192.168.0.12

Query board hardware info:

    sudo plctool -i enp0s31f6 -I
    sudo plctool -i enp0s31f6 -I 88:FC:A6:1C:81:BB

Capture PLC traffic:

    sudo tcpdump -i enp0s31f6 -e -n

Run standard pyslac EVSE:

    cd /opt/VehicleSecProject/slac_plain/pyslac
    make run-local-sudo-single

Run standard pyslac PEV:

    cd /opt/VehicleSecProject/slac_plain/pyslac
    make run-ev-slac

Run dh-based pyslac EVSE:

    cd /opt/VehicleSecProject/slac_dylan_ddh/pyslac
    sudo PYTHONPATH=/opt/VehicleSecProject/slac_dylan_ddh/pyslac python pyslac/examples/single_slac_session.py

Run dh-based pyslac PEV:

    cd /opt/VehicleSecProject/slac_dylan_ddh/pyslac
    sudo PYTHONPATH=/opt/VehicleSecProject/slac_dylan_ddh/pyslac python pyslac/examples/ev_slac_scapy.py

Restore PLC pairing after running pyslac:

    Press PAIR on PEV board (Board1)
    Within 60 seconds press PAIR on EVSE board (Board2)
    PLC LED will go solid green

---

## References

- ISO 15118-3: Vehicle to Grid Communication Interface
- HomePlug Green PHY Specification Release Version 1.1
- devolo dLAN Green PHY Eval Board II Data Sheet v1.00
- EcoG-io/pyslac: https://github.com/EcoG-io/pyslac
- dylanc1/pyslac dh-based: https://github.com/dylanc1/pyslac/tree/dh-based
- Qualcomm open-plc-utils: https://github.com/qca/open-plc-utils
- AcCCS project: https://github.com/IdahoLabResearch/AcCCS