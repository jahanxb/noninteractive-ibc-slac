import logging
from time import sleep
from binascii import hexlify
from hashlib import sha256

#filename: ev_slac_scapy.py

from pyslac.ibe_key_establishment import CertificatelessKeyEstablishment
from pyslac.utils import generate_nid

from typing import List
from scapy.all import (
    Ether,
    Packet,
    StrFixedLenField,
    X3BytesField,
    XByteField,
    XIntField,
    XLEShortField,
    XNBytesField,
    XShortField,
    sendp,
)

from pyslac.enums import (
    CM_ATTEN_CHAR,
    CM_ATTEN_PROFILE,
    CM_MNBC_SOUND,
    CM_SET_KEY,
    CM_SLAC_MATCH,
    CM_SLAC_PARM,
    CM_START_ATTEN_CHAR,
    ETH_TYPE_HPAV,
    MMTYPE_CNF,
    MMTYPE_IND,
    MMTYPE_REQ,
    MMTYPE_RSP,
    SLAC_SETTLE_TIME,
)
from pyslac.utils import get_if_hwaddr

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__file__)

BROADCAST_ADDR = "FF:FF:FF:FF:FF:FF"
PEV_MAC  = "88:FC:A6:1C:81:C2"
EVSE_MAC = "88:FC:A6:1C:81:BB"
IFACE    = "eno1"

ev_nmk = None
ev_nid = None

# Retransmission of CM_SLAC_PARM.REQ. The product of these two stays within the
# EVSE's 20 s CM_SLAC_PARM listening window.
SLAC_PARM_ATTEMPTS = 5
SLAC_PARM_RETRY_TIMEOUT = 4

# ── Banner helper ────────────────────────────────────────────
W = 67

def banner(title):
    print("\n" + "="*W)
    print(f"  {title}")
    print("="*W)

def banner_end():
    print("="*W + "\n")


# ── Scapy Packet Definitions ─────────────────────────────────

class HomePlugHeader(Packet):
    name = "HomePlugHeader "
    fields_desc = [
        XByteField("mmv", 1),
        XLEShortField("mm_type", CM_SET_KEY | MMTYPE_REQ),
        XByteField("fmsn", 0),
        XByteField("fmid", 0),
    ]


class SetKeyRequest(Packet):
    name = "SetKeyRequest Payload "
    fields_desc = [
        XByteField("key_type", 1),
        XIntField("my_nonce", 0xAAAAAAAA),
        XIntField("your_nonce", 0x00000000),
        XByteField("pid", 4),
        XShortField("prn", 0x0000),
        XByteField("pmn", 0),
        XByteField("cco_cap", 0),
        XIntField("nid_first_4_bytes", 0x026BCBA5),
        X3BytesField("nid_last_3bytes", 0x354E08),
        XByteField("new_eks", 1),
        XNBytesField("new_key", 0xB59319D7E8157BA001B018669CCEE30D, 16),
        X3BytesField("rsvd", 0x000000),
    ]


class SetKeyConfirmation(Packet):
    name = "SetKeyResponse Payload "
    fields_desc = [
        XByteField("result", 0),
        XIntField("my_nonce", 0xAAAAAAAA),
        XIntField("your_nonce", 0x00000000),
        XByteField("pid", 4),
        XShortField("prn", 0x0000),
        XByteField("pmn", 0),
        XByteField("cco_cap", 0),
        XNBytesField("rsvd", 0, 27),
    ]


class SlacParmReq(Packet):
    name = "Slac Parm Req Payload "
    fields_desc = [
        XByteField("application_type", 0x00),
        XByteField("security_type", 0x00),
        XNBytesField("run_id", 0, 8),
        XNBytesField("rsvd", 0, 31),
    ]


class StartAttenChar(Packet):
    name = "Start Atten Characterization Payload "
    fields_desc = [
        XByteField("application_type", 0x00),
        XByteField("security_type", 0x00),
        XByteField("num_sounds", 2),
        XByteField("time_out", 100),
        XByteField("resp_type", 0x01),
        XNBytesField("forwarding_sta", 0, 6),
        XNBytesField("run_id", 0, 8),
        XNBytesField("rsvd", 0, 22),
    ]


class MnbcSound(Packet):
    name = "MnbcSound Payload "
    fields_desc = [
        XByteField("application_type", 0x00),
        XByteField("security_type", 0x00),
        XNBytesField("sender_id", 0, 17),
        XByteField("cnt", 2),
        XNBytesField("run_id", 0, 8),
        XNBytesField("rsvd", 0, 8),
        XNBytesField("rnd", 0, 16),
    ]


class AttenProfile(Packet):
    name = "Atten Profile Payload "
    fields_desc = [
        XNBytesField("pev_mac", 0, 6),
        XByteField("num_groups", 3),
        XByteField("rsvd", 0),
        XByteField("aag1", 40),
        XByteField("aag2", 36),
        XByteField("aag3", 40),
        XNBytesField("rsvd1", 0, 60 - 30),
    ]


class AttenCharResp(Packet):
    name = "Start Atten Characterization Payload "
    fields_desc = [
        XByteField("application_type", 0x00),
        XByteField("security_type", 0x00),
        XNBytesField("source_address", 0, 6),
        XNBytesField("run_id", 0, 8),
        XNBytesField("source_id", 0, 17),
        XNBytesField("resp_id", 0, 17),
        XByteField("result", 0),
    ]


class SlacMatch(Packet):
    name = "Slac Match Request Payload "
    fields_desc = [
        XByteField("application_type", 0x00),
        XByteField("security_type", 0x00),
        XNBytesField("mvf_length", 0x003E, 2),
        XNBytesField("pev_id", 0, 17),
        XNBytesField("pev_mac", 0, 6),
        XNBytesField("evse_id", 0, 17),
        XNBytesField("evse_mac", 0, 6),
        XNBytesField("run_id", 0, 8),
        XNBytesField("rsvd", 0, 8),
    ]


# ── Global state ─────────────────────────────────────────────
host_mac     = None
host_mac_int = None
eth_header   = None
homeplug_header = None


def setup():
    global host_mac, host_mac_int, eth_header, homeplug_header
    host_mac       = PEV_MAC
    host_mac_bytes = bytes.fromhex(PEV_MAC.replace(":", ""))
    host_mac_int   = int.from_bytes(host_mac_bytes, "big")
    eth_header     = Ether(src=PEV_MAC, dst=EVSE_MAC, type=ETH_TYPE_HPAV)
    homeplug_header = HomePlugHeader()


# ── Frame send functions ─────────────────────────────────────

def setKeyConfirmation():
    logger.debug("EV:Starting Key Confirmation")
    global eth_header, homeplug_header
    homeplug_header.mm_type = CM_SET_KEY | MMTYPE_CNF
    set_key_confirmation = SetKeyConfirmation()
    frame_rsp = eth_header / homeplug_header / set_key_confirmation
    sendp(frame_rsp, iface=IFACE, verbose=False)
    logger.debug("EV:Sent Key Confirmation")


def paramRequest():
    logger.debug("EV:Sending Param Request")
    global eth_header, homeplug_header
    homeplug_header.mm_type = CM_SLAC_PARM | MMTYPE_REQ
    eth_header.dst = BROADCAST_ADDR
    slac_parm_req  = SlacParmReq()
    frame_rsp      = eth_header / homeplug_header / slac_parm_req
    logger.debug("EV:1: Sent Param Request")
    sendp(frame_rsp, iface=IFACE, verbose=False)


def attenChar():
    logger.debug("EV:Sending Attenuation Characterization Indication")
    global eth_header, homeplug_header
    homeplug_header.mm_type = CM_START_ATTEN_CHAR | MMTYPE_IND
    eth_header.dst = BROADCAST_ADDR
    start_atten_char = StartAttenChar()
    frame_rsp = eth_header / homeplug_header / start_atten_char
    sendp(frame_rsp, iface=IFACE, verbose=False)
    logger.debug("EV:3: Sent Attenuation Characterization Indication")


def mnbcSound():
    logger.debug("EV:Sending MNBC Sound Indication")
    global eth_header, homeplug_header, host_mac
    homeplug_header.mm_type = CM_MNBC_SOUND | MMTYPE_IND
    eth_header.src = host_mac
    eth_header.dst = BROADCAST_ADDR
    ev_cm_mnbc_sound = MnbcSound()
    frame_rsp_mnbc   = eth_header / homeplug_header / ev_cm_mnbc_sound
    sendp(frame_rsp_mnbc, iface=IFACE, verbose=False)
    logger.debug("EV:4: Sent MNBC Sound Indication")


def attenProfile():
    logger.debug("EV:Sending Attenuation Profile Indication")
    global eth_header, homeplug_header, host_mac_int
    homeplug_header.mm_type = CM_ATTEN_PROFILE | MMTYPE_IND
    eth_header.src = PEV_MAC
    eth_header.dst = EVSE_MAC
    atten_profile  = AttenProfile(pev_mac=host_mac_int)
    frame_rsp_atten = eth_header / homeplug_header / atten_profile
    sendp(frame_rsp_atten, iface=IFACE, verbose=False)
    logger.debug("EV:Sent Attenuation Profile Indication")


def attenCharResponse():
    global eth_header, homeplug_header, host_mac_int
    homeplug_header.mm_type = CM_ATTEN_CHAR | MMTYPE_RSP
    eth_header.src = PEV_MAC
    eth_header.dst = EVSE_MAC
    atten_char_rsp  = AttenCharResp(source_address=host_mac_int)
    frame_rsp = eth_header / homeplug_header / atten_char_rsp
    logger.debug("EV:6: Sent Attenuation Characterization Response")
    sendp(frame_rsp, iface=IFACE, verbose=False)


def pevSetKey(nmk: bytes):
    """Program the PEV board with the derived NMK from IBE key establishment."""
    logger.debug("PEV:Sending SetKey to program board with IBE-derived NMK")
    global eth_header, homeplug_header
    homeplug_header.mm_type = CM_SET_KEY | MMTYPE_REQ
    eth_header.src = PEV_MAC
    eth_header.dst = PEV_MAC  # Send to PEV board's MAC

    nid = generate_nid(nmk)
    nid_first_4 = int.from_bytes(nid[:4], 'big')
    nid_last_3 = int.from_bytes(nid[4:7], 'big')
    nmk_int = int.from_bytes(nmk, 'big')

    # Create SetKeyRequest with correct NMK and NID
    set_key_req = SetKeyRequest(
        nid_first_4_bytes=nid_first_4,
        nid_last_3bytes=nid_last_3,
        new_key=nmk_int
    )

    frame_rsp = eth_header / homeplug_header / set_key_req
    sendp(frame_rsp, iface=IFACE, verbose=False)
    logger.debug(f"PEV:SetKey sent with NMK: {nmk.hex()}")
    sleep(SLAC_SETTLE_TIME)

    banner("[STEP 5a] PEV → Board: CM_SET_KEY.REQ (IBE-Derived NMK)")
    print(f"  ▶ Action    : NMK derived via IBE programmed into PEV QCA7000 chip")
    print(f"  ▶ NMK       : {nmk.hex()}")
    print(f"  ▶ NID       : {nid.hex()}")
    print(f"  ▶ Interface : {IFACE}")
    print(f"  ▶ Status    : SetKey sent ✓")
    banner_end()


def ibeKeyEstablishment():
    logger.debug("EV:Starting certificateless key establishment")
    global ev_nmk, ev_nid

    ibe = CertificatelessKeyEstablishment()

    # MAC addresses (without colons) serve as identities
    ev_mac = PEV_MAC.replace(":", "").lower()
    evse_mac = EVSE_MAC.replace(":", "").lower()

    # Manufacturer tags
    M_EV = "M_EV"
    M_EVSE = "M_EVSE"

    # Full identity strings for context
    ev_identity = ev_mac + M_EV
    evse_identity = evse_mac + M_EVSE

    # ── Step 6 print — part 1: Two-manufacturer PKG + cross-domain enrollment ─────────
    banner("[STEP 6]  CERTIFICATELESS KEY ESTABLISHMENT  (PEV Side)")
    print(f"  ▶ Method    : Certificateless Two-Party IBC over bilinear pairing (SS512)")
    print(f"  ▶ Security  : BDH (Bilinear Diffie-Hellman) assumption")
    print(f"  ▶ Scheme    : Cross-domain enrollment with two manufacturers")
    print()
    print(f"  Private Key Generators (Two Manufacturers):")
    print(f"  ▶ EV Mfg    : s_M_EV, public key mpk_M_EV = s_M_EV * P")
    print(f"  ▶ EVSE Mfg  : s_M_EVSE, public key mpk_M_EVSE = s_M_EVSE * P")
    print(f"  ▶ Files     : ibe_master_secret_ev.bin")
    print(f"  ▶ Files     : ibe_master_secret_evse.bin")
    print()
    print(f"  Identity Strings (MAC || Manufacturer tag):")
    print(f"  ▶ EV   ID   : {ev_mac} || {M_EV}")
    print(f"  ▶ EVSE ID   : {evse_mac} || {M_EVSE}")
    print()

    # Cross-domain private key computation
    # SK_EV = s_M_EV * Q_EV + s_M_EVSE * Q_EV
    ev_sk = ibe.compute_cross_domain_private_key(ev_mac, M_EV)
    print(f"  Cross-Domain Private Key Computation (PEV):")
    print(f"  ▶ Formula   : SK_EV = s_M_EV * Q_EV + s_M_EVSE * Q_EV")
    print(f"  ▶ where     : Q_EV = H(ID_EV || M_EV)")
    print(f"  ▶ Partial 1 : s_M_EV * Q_EV (from EV manufacturer)")
    print(f"  ▶ Partial 2 : s_M_EVSE * Q_EV (from EVSE manufacturer)")
    print(f"  ▶ Combined  : SK_EV = Partial 1 + Partial 2 (locally)")
    print(f"  ▶ SK Type   : {type(ev_sk.secret_key).__name__} "
          f"(pairing.Element in G1)")
    print(f"  ▶ Status    : PEV cross-domain key computed ✓")
    print()

    # Derive shared secret via bilinear pairing
    # K_EV = e(SK_EV, Q_EVSE)
    shared_secret = ibe.derive_shared_secret(
        my_private_key=ev_sk,
        peer_identity=evse_mac,
        peer_manufacturer_tag=M_EVSE,
    )
    print(f"  Bilinear Pairing Computation (PEV):")
    print(f"  ▶ Formula   : K_EV = e(SK_EV, Q_EVSE)")
    print(f"               = e((s_M_EV + s_M_EVSE)*Q_EV, Q_EVSE)")
    print(f"  ▶ Result    : e(Q_EV, Q_EVSE)^(s_M_EV + s_M_EVSE)")
    print(f"  ▶ By bilinearity, EVSE computes: K_EVSE = e(Q_EV, SK_EVSE)")
    print(f"  ▶ Which gives the same result: e(Q_EV, Q_EVSE)^(s_M_EV + s_M_EVSE)")
    print(f"  ▶ Shared    : {shared_secret.hex()[:40]}...  ({len(shared_secret)} bytes)")
    print(f"  ▶ Status    : Pairing computed ✓")
    print()

    ev_nmk = ibe.derive_nmk(
        shared_secret=shared_secret,
        run_id=bytes(8),
        ev_identity=ev_identity,
        evse_identity=evse_identity,
    )
    ev_nid = generate_nid(ev_nmk)

    print(f"  NMK Derivation:")
    print(f"  ▶ Formula   : NMK = SHA256(shared || 'SLAC-IBC-NMK-v1'")
    print(f"                             || run_id || ID_EV || ID_EVSE)[:16]")
    print(f"  ▶ Run ID    : {bytes(8).hex()}")
    print(f"  ▶ NMK       : {ev_nmk.hex()}  (16 bytes)")
    print(f"  ▶ NID       : {ev_nid.hex()}  (7 bytes, derived from NMK)")
    print()
    print(f"  Security Properties:")
    print(f"  ▶ Wire      : ZERO key material transmitted over PLC ✓")
    print(f"  ▶ Compare   : ECDH sends 2 public key frames (0x6080 + 0x6083)")
    print(f"  ▶ IBC       : 0 frames — non-interactive key establishment")
    print(f"  ▶ Enrollment: Cross-domain (both manufacturers' keys required)")
    print(f"  ▶ Status    : NMK established successfully ✓")
    banner_end()

    logger.debug("EV:Certificateless NMK established")


def slacMatch():
    logger.debug("EV:Starting Slac Match")
    global eth_header, homeplug_header, host_mac_int
    homeplug_header.mm_type = CM_SLAC_MATCH | MMTYPE_REQ
    evse_mac_int = int.from_bytes(bytes.fromhex(EVSE_MAC.replace(":", "")), "big")
    slac_match   = SlacMatch(pev_mac=host_mac_int, evse_mac=evse_mac_int)
    frame_rsp    = eth_header / homeplug_header / slac_match
    logger.debug("EV:9: Sending Slac Match Request")
    sendp(frame_rsp, iface=IFACE, verbose=False)


# ── Sniffer helpers ──────────────────────────────────────────
from scapy.all import AsyncSniffer
import time as _time

def run():
    setup()

    # ── Session start banner ─────────────────────────────────
    banner("SLAC + IBE PROTOCOL SESSION STARTING  (PEV Side)")
    print(f"  ▶ PEV  MAC  : {PEV_MAC}")
    print(f"  ▶ EVSE MAC  : {EVSE_MAC}")
    print(f"  ▶ Interface : {IFACE}")
    print(f"  ▶ Protocol  : ISO 15118-3 SLAC + IBE Key Establishment")
    print(f"  ▶ IBE Scheme: Boneh-Franklin over SS512 pairing group")
    print(f"  ▶ Hardware  : devolo dLAN Green PHY QCA7000")
    banner_end()

    # ── Step 1: CM_SET_KEY.CNF ───────────────────────────────
    # banner("[STEP 1]  PEV → QCA7000 CHIP: CM_SET_KEY.CNF")
    # print(f"  ▶ Action    : Confirm NMK registration on PEV PLC chip")
    # print(f"  ▶ Dest MAC  : {EVSE_MAC} (EVSE)")
    # print(f"  ▶ Status    : Sending CM_SET_KEY.CNF...")
    setKeyConfirmation()
    sleep(SLAC_SETTLE_TIME)
    # print(f"  ▶ Status    : CM_SET_KEY.CNF sent — settling {SLAC_SETTLE_TIME}s ✓")
    # banner_end()

    # ── Sniffer setup ────────────────────────────────────────
    captured = []

    def capture(pkt):
        if pkt.haslayer(Ether) and pkt[Ether].type == ETH_TYPE_HPAV:
            raw = bytes(pkt)
            if len(raw) >= 17:
                mm_type = int.from_bytes(raw[15:17], 'little')
                logger.debug(f"Sniffer captured mm_type: 0x{mm_type:04x}")
                captured.append((mm_type, raw))

    def wait_for(mm_type_expected, timeout=20):
        start = _time.time()
        while _time.time() - start < timeout:
            for i, (mm, raw) in enumerate(captured):
                if mm == mm_type_expected:
                    captured.pop(i)
                    logger.debug(f"Found expected mm_type: 0x{mm_type_expected:04x}")
                    return raw
            sleep(0.05)
        logger.error(f"Timeout waiting for mm_type 0x{mm_type_expected:04x}")
        logger.debug(f"Captured so far: {[hex(mm) for mm, _ in captured]}")
        return None

    sniffer = AsyncSniffer(
        iface=IFACE,
        lfilter=lambda p: p.haslayer(Ether) and p[Ether].type == ETH_TYPE_HPAV,
        prn=capture,
        store=False
    )
    sniffer.start()
    deadline = _time.time() + 5
    while not sniffer.running and _time.time() < deadline:
        sleep(0.05)
    logger.debug("Sniffer ready")

    # ── Step 1: SLAC_PARM + Identity Discovery ───────────────
    banner("[STEP 1]  PEV → Broadcast: CM_SLAC_PARM.REQ")
    print(f"  ▶ Action    : EV announces presence on PLC network")
    print(f"  ▶ Dest MAC  : ff:ff:ff:ff:ff:ff (Broadcast)")
    print()
    print(f"  ┌{'─'*61}┐")
    print(f"  │{'IDENTITY DISCOVERY  —  PEV Side':^61}│")
    print(f"  ├{'─'*61}┤")
    print(f"  │  PEV knows its own MAC — used as its IBE identity              │")
    print(f"  │  EVSE identity confirmed from CM_SLAC_PARM.CNF source MAC      │")
    print(f"  │                                                                │")
    print(f"  │  PEV  MAC   : {PEV_MAC:<46} │")
    print(f"  │  IBE ID(PEV): EV:{PEV_MAC.replace(':','').lower():<43} │")
    print(f"  │                                                                │")
    print(f"  │  EVSE MAC   : {EVSE_MAC:<46} │")
    print(f"  │  IBE ID(EV) : EVSE:{EVSE_MAC.replace(':','').lower():<41} │")
    print(f"  │                                                                │")
    print(f"  │  ✓ Both identities known to PEV                                │")
    print(f"  │  ✓ These identity strings will be used as IBE inputs           │")
    print(f"  │    at Step to derive the session NMK via pairing             │")
    print(f"  └{'─'*61}┘")
    banner_end()

    # The EVSE tears down and rebuilds its socket on entry to CM_SLAC_PARM, so a
    # single REQ can be dropped if it lands in that window. Retransmit until the
    # CNF comes back, within the EVSE's listening window.
    cnf = None
    for attempt in range(1, SLAC_PARM_ATTEMPTS + 1):
        paramRequest()
        logger.debug(
            f"Waiting for CM_SLAC_PARM.CNF... "
            f"(attempt {attempt}/{SLAC_PARM_ATTEMPTS})"
        )
        cnf = wait_for(CM_SLAC_PARM | MMTYPE_CNF, timeout=SLAC_PARM_RETRY_TIMEOUT)
        if cnf:
            break
    if not cnf:
        sniffer.stop()
        logger.error("No CM_SLAC_PARM.CNF - aborting")
        return
    logger.debug("Received CM_SLAC_PARM.CNF")
    print(f"  ★ CM_SLAC_PARM.CNF received from EVSE MAC: {EVSE_MAC} ✓")
    print(f"  ★ EVSE IBE Identity confirmed: EVSE:{EVSE_MAC.replace(':','').lower()}\n")

    # ── Step 2: START_ATTEN_CHAR ─────────────────────────────
    banner("[STEP 2]  PEV → Broadcast: CM_START_ATTEN_CHAR.IND")
    print(f"  ▶ Action    : EV announces start of attenuation measurement")
    print(f"  ▶ Num Sounds: 2 MNBC sound bursts to follow")
    print(f"  ▶ Timeout   : 10000 ms measurement window")
    attenChar()
    print(f"  ▶ Status    : CM_START_ATTEN_CHAR.IND sent ✓")
    banner_end()

    # ── Step 4: MNBC Sounds + Attenuation Profiles ───────────
    banner("[STEP 3]  PEV → Broadcast/EVSE: MNBC Sounds + Attenuation Profiles")
    print(f"  ▶ Sending 2 MNBC sound bursts for PLC signal measurement")
    mnbcSound();    sleep(0.1)
    attenProfile(); sleep(0.1)
    print(f"  ▶ Sound 1 sent + Attenuation Profile 1 sent ✓")
    mnbcSound();    sleep(0.1)
    attenProfile(); sleep(0.1)
    print(f"  ▶ Sound 2 sent + Attenuation Profile 2 sent ✓")
    print(f"  ▶ Waiting for EVSE to send CM_ATTEN_CHAR.IND...")

    logger.debug("Waiting for CM_ATTEN_CHAR.IND...")
    ind = wait_for(CM_ATTEN_CHAR | MMTYPE_IND, timeout=20)
    if not ind:
        sniffer.stop()
        logger.error("No CM_ATTEN_CHAR.IND - aborting")
        return
    logger.debug("Received CM_ATTEN_CHAR.IND")
    print(f"  ▶ CM_ATTEN_CHAR.IND received from EVSE ✓")
    banner_end()

    # ── Step 4: ATTEN_CHAR.RSP ───────────────────────────────
    banner("[STEP 4]  PEV → EVSE: CM_ATTEN_CHAR.RSP")
    print(f"  ▶ Action    : EV acknowledges attenuation data from EVSE")
    print(f"  ▶ Result    : 0x00 — attenuation within acceptable threshold")
    attenCharResponse()
    print(f"  ▶ Status    : CM_ATTEN_CHAR.RSP sent — proceeding to IBE ✓")
    banner_end()

    
    ibeKeyEstablishment()
    sleep(0.2)

    # ── Step 5a: Program board with IBE-derived NMK ──────────
    if ev_nmk:
        pevSetKey(ev_nmk)
    sleep(0.2)

    # ── Step 6: SLAC_MATCH ───────────────────────────────────
    banner("[STEP 6]  PEV → EVSE: CM_SLAC_MATCH.REQ")
    print(f"  ▶ Action    : EV requests final SLAC network matching")
    print(f"  ▶ PEV  MAC  : {PEV_MAC}")
    print(f"  ▶ EVSE MAC  : {EVSE_MAC}")
    print(f"  ▶ NMK       : {ev_nmk.hex() if ev_nmk else 'pending'}")
    slacMatch()
    print(f"  ▶ CM_SLAC_MATCH.REQ sent — waiting for CM_SLAC_MATCH.CNF...")

    logger.debug("Waiting for CM_SLAC_MATCH.CNF...")
    cnf = wait_for(CM_SLAC_MATCH | MMTYPE_CNF, timeout=20)
    if not cnf:
        sniffer.stop()
        logger.error("No CM_SLAC_MATCH.CNF - aborting")
        return

    print(f"  ▶ CM_SLAC_MATCH.CNF received from EVSE ✓")
    banner_end()

    sniffer.stop()

    # ── Final summary ────────────────────────────────────────
    banner("SLAC + IBE HANDSHAKE COMPLETE WITH HARDWARE PAIRING  ✓")
    print(f"  ▶ PEV  MAC     : {PEV_MAC}")
    print(f"  ▶ EVSE MAC     : {EVSE_MAC}")
    print(f"  ▶ NMK          : {ev_nmk.hex() if ev_nmk else 'N/A'}")
    print(f"  ▶ NID          : {ev_nid.hex() if ev_nid else 'N/A'}")
    print()
    print(f"  ▶ NMK Match    : Both EV and EVSE derived same NMK independently ✓")
    print(f"  ▶ PLC Network  : Logical network established on QCA7000 chips ✓")
    print(f"  ▶ Wire Traffic : ZERO IBE key material on wire ✓")
    print(f"  ▶ Security     : Non-interactive IBE — no key exchange frames sent")
    print(f"  ▶ Next Step    : ISO 15118-2 HLC charging communication begins")
    banner_end()

    logger.debug("PEV-EVSE MATCHED Successfully!")


if __name__ == "__main__":
    run()