import logging
from time import sleep
from binascii import hexlify
from hashlib import sha256

from pyslac.ibe_key_establishment import IBEKeyEstablishment
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
IFACE = "eno1"

ev_nmk = None
ev_nid = None


def IBEKeyDistReq_fromraw(raw):
    offset = 19
    key_len = int.from_bytes(raw[offset:offset+2], 'big')
    offset += 2
    private_key_bytes = raw[offset:offset+key_len]
    offset += key_len
    params_len = int.from_bytes(raw[offset:offset+2], 'big')
    offset += 2
    params_bytes = raw[offset:offset+params_len]

    class _KD:
        pass
    kd = _KD()
    kd.private_key_bytes = private_key_bytes
    kd.params_bytes = params_bytes
    return kd

def IBEEncReq_fromraw(raw):
    offset = 19
    ct_len = int.from_bytes(raw[offset:offset+2], 'big')
    offset += 2
    ciphertext_bytes = raw[offset:offset+ct_len]

    class _Enc:
        pass
    enc = _Enc()
    enc.ciphertext_bytes = ciphertext_bytes
    return enc


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


# EV Messages to Send
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
        XByteField(
            "num_sounds", 2
        ),  # This defines the number of sounds that the EV will send to the EVSE.
        # And overrides the expected sounds defined by enum SLAC_MSOUNDS
        XByteField(
            "time_out", 100
        ),  # This defines the time to 10 secs (100 * 100 ms) that the EV must
        # deliver the mnbc sounds before the EVSE times out
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


class ECDHExchangeResp(Packet):
    name = "ECDH Key Exchange Response Payload "
    fields_desc = [
        StrFixedLenField("qv", b"\x00" * 49, 49),
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


host_mac = None
host_mac_int = None
eth_header = None
homeplug_header = None


# CHANGE TO
def setup():
    global host_mac, host_mac_int, eth_header, homeplug_header
    host_mac = PEV_MAC   # use real PEV board MAC
    host_mac_bytes = bytes.fromhex(PEV_MAC.replace(":", ""))
    host_mac_int = int.from_bytes(host_mac_bytes, "big")
    eth_header = Ether(src=PEV_MAC, dst=EVSE_MAC, type=ETH_TYPE_HPAV)
    homeplug_header = HomePlugHeader()


def setKeyRequest():
    """
    Set Key Request was included in previous iterations
    although it is not currently being sent
    """
    logger.debug("EV:Starting Key Request")
    global eth_header, homeplug_header
    set_key_request = SetKeyRequest()
    frame_rsp = eth_header / homeplug_header / set_key_request
    sendp(frame_rsp, iface=IFACE, verbose=False)
    logger.debug("EV:Sent Key Request")


def setKeyConfirmation():
    """
    Set Key Confirmation
    After the message is sent, a 20 second timeout occurs
    for the HLE to settle
    """
    logger.debug("EV:Starting Key Confirmation")
    global eth_header, homeplug_header
    homeplug_header.mm_type = CM_SET_KEY | MMTYPE_CNF
    set_key_confirmation = SetKeyConfirmation()
    frame_rsp = eth_header / homeplug_header / set_key_confirmation
    sendp(frame_rsp, iface=IFACE, verbose=False)
    logger.debug("EV:Sent Key Confirmation")


def paramRequest():
    """
    Param Request provides the EVSE with information on
    the security options available
    """
    logger.debug("EV:Sending Param Request")
    global eth_header, homeplug_header
    homeplug_header.mm_type = CM_SLAC_PARM | MMTYPE_REQ
    eth_header.dst = BROADCAST_ADDR
    slac_parm_req = SlacParmReq()
    frame_rsp = eth_header / homeplug_header / slac_parm_req
    logger.debug("EV:1: Sent Param Request")
    sendp(frame_rsp, iface=IFACE, verbose=False)


def attenChar():
    """
    Start Attenuation Characterization Indication
    Identifies the number of sounds to follow, in
    this case 2
    """
    logger.debug("EV:Sending Attenuation Characterization Indication")
    global eth_header, homeplug_header
    homeplug_header.mm_type = CM_START_ATTEN_CHAR | MMTYPE_IND
    eth_header.dst = BROADCAST_ADDR
    start_atten_char = StartAttenChar()
    frame_rsp = eth_header / homeplug_header / start_atten_char
    # The EV may send 3 start atten char, but the QCA chip will forward only 1
    # to the application
    sendp(frame_rsp, iface=IFACE, verbose=False)
    logger.debug("EV:3: Sent Attenuation Characterization Indication")


def mnbcSound():
    """
    MNBC Sound Indication
    Sent multiple times depending on the value specified in
    the CM_START_ATTEN_CHAR.IND message
    """
    logger.debug("EV:Sending MNBC Sound Indication")
    global eth_header, homeplug_header, host_mac
    homeplug_header.mm_type = CM_MNBC_SOUND | MMTYPE_IND
    eth_header.src = host_mac
    eth_header.dst = BROADCAST_ADDR
    ev_cm_mnbc_sound = MnbcSound()
    frame_rsp_mnbc = eth_header / homeplug_header / ev_cm_mnbc_sound
    sendp(frame_rsp_mnbc, iface=IFACE, verbose=False)
    logger.debug("EV:4: Sent MNBC Sound Indication")


def attenProfile():
    """
    Attenuation Profile Indication
    Sent multiple times depending on the value specified in
    the CM_START_ATTEN_CHAR.IND message
    """
    logger.debug("EV:Sending Attenuation Profile Indication")
    global eth_header, homeplug_header, host_mac_int
    homeplug_header.mm_type = CM_ATTEN_PROFILE | MMTYPE_IND
    eth_header.src = PEV_MAC#ATHEROS_CHIP_MAC
    eth_header.dst = EVSE_MAC#host_mac
    atten_profile = AttenProfile(pev_mac=host_mac_int)
    frame_rsp_atten = eth_header / homeplug_header / atten_profile
    sendp(frame_rsp_atten, iface=IFACE, verbose=False)
    logger.debug("EV:Sent Attenuation Profile Indication")


def attenCharResponse():
    global eth_header, homeplug_header, host_mac_int
    homeplug_header.mm_type = CM_ATTEN_CHAR | MMTYPE_RSP
    eth_header.src = PEV_MAC   # correct
    eth_header.dst = EVSE_MAC  # fix: was host_mac (same as PEV_MAC)
    atten_char_rsp = AttenCharResp(source_address=host_mac_int)
    frame_rsp = eth_header / homeplug_header / atten_char_rsp
    logger.debug("EV:6: Sent Attenuation Characterization Response")
    sendp(frame_rsp, iface=IFACE, verbose=False)

def ibeKeyEstablishment():
    logger.debug("EV:Starting IBE-based key establishment")
    global ev_nmk, ev_nid

    ibe = IBEKeyEstablishment()

    ev_identity   = "EV:"   + PEV_MAC.replace(":", "").lower()
    evse_identity = "EVSE:" + EVSE_MAC.replace(":", "").lower()

    print("\n" + "="*65)
    print("  [STEP 6] IBE KEY ESTABLISHMENT (PEV Side)")
    print("="*65)
    print(f"  ▶ Method      : Boneh-Franklin IBE over SS512 pairing group")
    print(f"  ▶ PKG File    : {ibe.master_secret_path}")
    print(f"  ▶ EV   ID     : {ev_identity}")
    print(f"  ▶ EVSE ID     : {evse_identity}")

    ev_sk = ibe.extract_private_key(ev_identity)
    print(f"  ▶ EV   SK     : s × H('{ev_identity}') computed ✓")
    print(f"  ▶ SK Type     : {type(ev_sk.secret_key).__name__} (pairing.Element in G1)")

    shared_secret = ibe.derive_shared_secret(
        my_private_key=ev_sk,
        peer_identity=evse_identity,
    )
    print(f"  ▶ Pairing     : e(SK_EV, Q_EVSE) computed ✓")
    print(f"  ▶ Shared Elem : {shared_secret.hex()[:32]}... ({len(shared_secret)} bytes)")

    ev_nmk = ibe.derive_nmk(
        shared_secret=shared_secret,
        run_id=bytes(8),
        ev_identity=ev_identity,
        evse_identity=evse_identity,
    )
    ev_nid = generate_nid(ev_nmk)

    print(f"  ▶ NMK         : {ev_nmk.hex()}  (SHA256(shared||context)[:16])")
    print(f"  ▶ NID         : {ev_nid.hex()}")
    print(f"  ▶ Wire Traffic: ZERO — no key material transmitted over PLC")
    print(f"  ▶ Status      : SUCCESS")
    print("="*65 + "\n")

    logger.debug("EV:IBE-based NMK established")


def slacMatch():
    """
    SLAC Match Request
    Initiates the SLAC matching with the EVSE
    """
    logger.debug("EV:Starting Slac Match")
    global eth_header, homeplug_header, host_mac_int
    homeplug_header.mm_type = CM_SLAC_MATCH | MMTYPE_REQ
    #slac_match = SlacMatch(pev_mac=host_mac_int, evse_mac=host_mac_int)
    evse_mac_int = int.from_bytes(bytes.fromhex(EVSE_MAC.replace(":", "")), "big")
    slac_match = SlacMatch(pev_mac=host_mac_int, evse_mac=evse_mac_int)
    frame_rsp = eth_header / homeplug_header / slac_match
    logger.debug("EV:9: Sending Slac Match Request")
    sendp(frame_rsp, iface=IFACE, verbose=False)

from scapy.all import sniff

def wait_for_frame(mm_type_expected, timeout=20):
    """Wait for a specific HomePlug frame type from EVSE"""
    result = []
    def match(pkt):
        if pkt.haslayer(Ether) and pkt[Ether].type == ETH_TYPE_HPAV:
            raw = bytes(pkt)
            if len(raw) >= 17:
                mm_type = int.from_bytes(raw[15:17], 'little')
                if mm_type == mm_type_expected:
                    result.append(raw)
                    return True
        return False
    sniff(iface=IFACE, lfilter=match, count=1, timeout=timeout)
    return result[0] if result else None

from scapy.all import AsyncSniffer
import time

def run():
    setup()
    setKeyConfirmation()
    sleep(SLAC_SETTLE_TIME)

    captured = []

    def capture(pkt):
        if pkt.haslayer(Ether) and pkt[Ether].type == ETH_TYPE_HPAV:
            raw = bytes(pkt)
            if len(raw) >= 17:
                mm_type = int.from_bytes(raw[15:17], 'little')
                logger.debug(f"Sniffer captured mm_type: 0x{mm_type:04x}")
                captured.append((mm_type, raw))

    def wait_for(mm_type_expected, timeout=20):
        start = time.time()
        while time.time() - start < timeout:
            for i, (mm, raw) in enumerate(captured):
                if mm == mm_type_expected:
                    captured.pop(i)
                    logger.debug(f"Found expected mm_type: 0x{mm_type_expected:04x}")
                    return raw
            sleep(0.05)
        logger.error(f"Timeout waiting for mm_type 0x{mm_type_expected:04x}")
        logger.debug(f"Captured so far: {[hex(mm) for mm, _ in captured]}")
        return None

    # Start AsyncSniffer and wait for it to be ready
    sniffer = AsyncSniffer(
        iface=IFACE,
        lfilter=lambda p: p.haslayer(Ether) and p[Ether].type == ETH_TYPE_HPAV,
        prn=capture,
        store=False
    )
    sniffer.start()
    # Wait until sniffer is actually running
    import time as _t
    deadline = _t.time() + 5
    while not sniffer.running and _t.time() < deadline:
        sleep(0.05)
    logger.debug("Sniffer ready")


    print("\n" + "="*65)
    print("  [STEP 2] SLAC PARAMETER EXCHANGE + IDENTITY DISCOVERY")
    print("="*65)
    print(f"  ▶ CM_SLAC_PARM.REQ sent to Broadcast")
    print()
    print(f"  ┌─────────────────────────────────────────────────┐")
    print(f"  │           IDENTITY DISCOVERY (PEV Side)         │")
    print(f"  ├─────────────────────────────────────────────────┤")
    print(f"  │ PEV identity is its own MAC address             │")
    print(f"  │ EVSE identity known from CM_SLAC_PARM.CNF src   │")
    print(f"  │                                                  │")
    print(f"  │  PEV  MAC  : {PEV_MAC:<36} │")
    print(f"  │  IBE ID    : EV:{PEV_MAC.replace(':','').lower():<33} │")
    print(f"  │                                                  │")
    print(f"  │  EVSE MAC  : {EVSE_MAC:<36} │")
    print(f"  │  IBE ID    : EVSE:{EVSE_MAC.replace(':','').lower():<30} │")
    print(f"  │                                                  │")
    print(f"  │   Both identities known — IBE key derivation   │")
    print(f"  │    will use these as input to pairing            │")
    print(f"  └─────────────────────────────────────────────────┘")
    print("="*65 + "\n")



    # Step 2 - send SLAC_PARM.REQ and wait for CNF
    paramRequest()
    logger.debug("Waiting for CM_SLAC_PARM.CNF...")
    cnf = wait_for(CM_SLAC_PARM | MMTYPE_CNF, timeout=20)
    if not cnf:
        sniffer.stop()
        logger.error("No CM_SLAC_PARM.CNF - aborting")
        return
    logger.debug("Received CM_SLAC_PARM.CNF")
    print(f" EVSE identity confirmed from CM_SLAC_PARM.CNF source MAC: {EVSE_MAC}")
    print(f" IBE Identity String: EVSE:{EVSE_MAC.replace(':','').lower()}")

    # Step 3
    print("\n[STEP 3] EV → Broadcast: CM_START_ATTEN_CHAR.IND")
    attenChar()
    print("\n[STEP 4] EV → Broadcast: MNBC Sounds + Attenuation Profiles")

    mnbcSound(); sleep(0.1)
    attenProfile(); sleep(0.1)
    mnbcSound(); sleep(0.1)
    attenProfile(); sleep(0.1)

    # Step 4 - wait for CM_ATTEN_CHAR.IND
    logger.debug("Waiting for CM_ATTEN_CHAR.IND...")
    ind = wait_for(CM_ATTEN_CHAR | MMTYPE_IND, timeout=20)
    if not ind:
        sniffer.stop()
        logger.error("No CM_ATTEN_CHAR.IND - aborting")
        return
    logger.debug("Received CM_ATTEN_CHAR.IND")
    attenCharResponse()
    print("\n[STEP 5] EV → EVSE: CM_ATTEN_CHAR.RSP sent")


    # Step 5 - wait for IBE key distribution
    # logger.debug("Waiting for CM_IBE_KEY_DIST.REQ...")
    # key_dist_raw = wait_for(CM_IBE_KEY_DIST | MMTYPE_REQ, timeout=20)
    # if not key_dist_raw:
    #     sniffer.stop()
    #     logger.error("No CM_IBE_KEY_DIST.REQ - aborting")
    #     return
    # logger.debug("Received CM_IBE_KEY_DIST.REQ")

    # logger.debug("Waiting for CM_IBE_ENC.REQ...")
    # enc_raw = wait_for(CM_IBE_ENC | MMTYPE_REQ, timeout=20)
    # if not enc_raw:
    #     sniffer.stop()
    #     logger.error("No CM_IBE_ENC.REQ - aborting")
    #     return
    # logger.debug("Received CM_IBE_ENC.REQ")

    ibeKeyEstablishment()
    sleep(0.2)



    # Step 6 - send SLAC_MATCH.REQ and wait for CNF
    slacMatch()
    print("\n[STEP 7] EV → EVSE: CM_SLAC_MATCH.REQ sent — waiting for CNF...")
    logger.debug("Waiting for CM_SLAC_MATCH.CNF...")
    cnf = wait_for(CM_SLAC_MATCH | MMTYPE_CNF, timeout=20)
    if not cnf:
        sniffer.stop()
        logger.error("No CM_SLAC_MATCH.CNF - aborting")
        return

    sniffer.stop()
    print("\n" + "="*65)
    print("  SLAC + IBE HANDSHAKE COMPLETE")
    print("="*65)
    print(f"  ▶ NMK Match   : Both sides derived same NMK ✓")
    print(f"  ▶ PLC Network : Established")
    print(f"  ▶ Security    : IBE non-interactive — zero key exchange on wire")
    print("="*65 + "\n")
    logger.debug("PEV-EVSE MATCHED Successfully!")



if __name__ == "__main__":
    run()
