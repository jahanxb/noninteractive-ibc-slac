import logging
from time import sleep
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

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
    CM_ECDH_EXCHANGE,
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
ATHEROS_CHIP_MAC = "00:b0:52:00:00:01"
IFACE = "eno1"


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


def setup():
    """
    Setup of global variables used in other functions
    as well as general Ethernet and HomePlug headers
    """
    logger.debug("EV:Starting Setup")
    global host_mac, host_mac_int, eth_header, homeplug_header
    host_mac = get_if_hwaddr(IFACE, to_mac_fmt=True)
    host_mac_bytes = get_if_hwaddr(IFACE, to_mac_fmt=False)
    host_mac_int = int.from_bytes(host_mac_bytes, "big")
    eth_header = Ether(src=host_mac, dst=ATHEROS_CHIP_MAC, type=ETH_TYPE_HPAV)
    homeplug_header = HomePlugHeader()
    logger.debug("EV:Finished Setup")


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
    eth_header.src = ATHEROS_CHIP_MAC
    eth_header.dst = host_mac
    atten_profile = AttenProfile(pev_mac=host_mac_int)
    frame_rsp_atten = eth_header / homeplug_header / atten_profile
    sendp(frame_rsp_atten, iface=IFACE, verbose=False)
    logger.debug("EV:Sent Attenuation Profile Indication")


def attenCharResponse():
    """
    Attenuation Characterization Response
    """
    logger.debug("EV:Sending Attenuation Characterization Response")
    global eth_header, homeplug_header, host_mac_int
    homeplug_header.mm_type = CM_ATTEN_CHAR | MMTYPE_RSP
    eth_header.src = host_mac
    eth_header.dst = host_mac
    atten_char_rsp = AttenCharResp(source_address=host_mac_int)
    frame_rsp = eth_header / homeplug_header / atten_char_rsp
    logger.debug("EV:6: Sent Attenuation Characterization Response")
    sendp(frame_rsp, iface=IFACE, verbose=False)


def ecdhExchange():
    """
    Elliptic Curve Diffie-Hellman Key Exchange
    Utilizes the cryptography python library to generate
    a private and public key pair from a common elliptic
    curve
    """
    logger.debug("EV:Starting ECDH Exchange")
    global eth_header, homeplug_header

    # Generates a private key from an elliptic curve shared by the EVSE
    private_key = ec.generate_private_key(ec.SECP192R1())
    # x = private_key.private_numbers().private_value

    # Extracts the private key and serializes it to be sent to the EVSE
    public_key = private_key.public_key()
    qv_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    print("Public key: %s" % qv_bytes)

    # Creates the message with the serialized public key
    homeplug_header.mm_type = CM_ECDH_EXCHANGE | MMTYPE_RSP
    ecdh_exchange_resp = ECDHExchangeResp(qv=qv_bytes)
    frame_rsp = eth_header / homeplug_header / ecdh_exchange_resp

    logger.debug("EV:8: Sending ECDH Exchange Response")
    sendp(frame_rsp, iface=IFACE, verbose=False)


def slacMatch():
    """
    SLAC Match Request
    Initiates the SLAC matching with the EVSE
    """
    logger.debug("EV:Starting Slac Match")
    global eth_header, homeplug_header, host_mac_int
    homeplug_header.mm_type = CM_SLAC_MATCH | MMTYPE_REQ
    slac_match = SlacMatch(pev_mac=host_mac_int, evse_mac=host_mac_int)
    frame_rsp = eth_header / homeplug_header / slac_match
    logger.debug("EV:9: Sending Slac Match Request")
    sendp(frame_rsp, iface=IFACE, verbose=False)


def run():
    """
    Run the entire script using this function
    """
    setup()

    setKeyConfirmation()

    # We need to wait SLAC_SETTLE_TIME because is the time the EVSE will wait
    # after receiving the SET_KEY_CNF for the HLE to settle. In a real EV
    # simulator, this wouldnt be  needed
    sleep(SLAC_SETTLE_TIME)
    # Slac Parm Req
    sleep(10)
    paramRequest()
    # Start Atten Char
    attenChar()

    # MNBC Sound
    # Send 2 times, since we defined 2 num of sounds in StartAttenChar
    # AttenProfile
    #  Send 2 times, since we defined 2 num of sounds in StartAttenChar
    mnbcSound()
    sleep(0.1)
    attenProfile()
    sleep(0.1)
    mnbcSound()
    sleep(0.1)
    attenProfile()
    sleep(0.1)

    # EV Receives a Atten Char Indicator and shall respond with Response
    # Unicast
    attenCharResponse()
    sleep(0.2)

    ecdhExchange()
    print('Sent ECDH Exchange frame')
    sleep(0.2)

    # EV does the Atten threshold calculation and evaluation, then sends a Match
    slacMatch()
    # Then the EV Should receive a Match conf with the NMK and NID so he can
    # join the network


if __name__ == "__main__":
    run()
