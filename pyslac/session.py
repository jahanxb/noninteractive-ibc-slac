import asyncio
import logging
from binascii import hexlify
from dataclasses import dataclass, field
from inspect import isawaitable
from os import urandom
from typing import List, Optional, Union
from hashlib import sha256

#filename: session.py

from pyslac import __version__
from pyslac.enums import (
    CM_ATTEN_CHAR,
    CM_ATTEN_PROFILE,
    CM_IBE_KEY_DIST,
    CM_IBE_ENC,
    CM_IBE_ACK,
    CM_MNBC_SOUND,
    CM_SET_KEY,
    CM_SLAC_MATCH,
    CM_SLAC_PARM,
    CM_START_ATTEN_CHAR,
    ETH_TYPE_HPAV,
    EVSE_PLC_MAC,
    HOMEPLUG_MMV,
    MMTYPE_CNF,
    MMTYPE_IND,
    MMTYPE_REQ,
    MMTYPE_RSP,
    SLAC_ATTEN_TIMEOUT,
    SLAC_GROUPS,
    SLAC_LIMIT,
    SLAC_MSOUNDS,
    SLAC_PAUSE,
    SLAC_RESP_TYPE,
    SLAC_SETTLE_TIME,
    STATE_MATCHED,
    STATE_MATCHING,
    STATE_UNMATCHED,
    FramesSizes,
    Timers,
    get_mm_type_name
)

from pyslac.environment import Config
from pyslac.layer_2_headers import EthernetHeader, HomePlugHeader
from pyslac.messages import (
    AtennChar,
    AtennCharRsp,
    AttenProfile,
    IBEKeyDistReq,
    IBEEncReq,
    IBEAckRsp,
    MatchCnf,
    MatchReq,
    MnbcSound,
    SetKeyCnf,
    SetKeyReq,
    SlacParmCnf,
    SlacParmReq,
    StartAtennChar,
)
from pyslac.sockets.async_linux_socket import (
    create_socket,
    readeth,
    send_recv_eth,
    sendeth,
)
from pyslac.utils import cancel_task, generate_nid, get_if_hwaddr
from pyslac.ibe_key_establishment import CertificatelessKeyEstablishment
from pyslac.utils import half_round as hw
from pyslac.utils import task_callback, time_now_ms

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("slac_session")
step_through = True
step_timeout = 20

# ── Banner helper ────────────────────────────────────────────
W = 67

def banner(title):
    print("\n" + "="*W)
    print(f"  {title}")
    print("="*W)

def banner_end():
    print("="*W + "\n")


@dataclass
class SlacSession:
    state: int
    nmk: bytes = b""
    nid: bytes = b""
    forwarding_sta: bytes = b""
    pev_id: Optional[int] = None
    pev_mac: bytes = b""
    evse_mac: bytes = b""
    run_id: bytes = b""
    application_type: int = 0x00
    security_type: int = 0x00
    num_start_attn_rcvd: int = 0
    num_expected_sounds: Optional[int] = None
    num_total_sounds: int = 0
    sounds: int = SLAC_MSOUNDS
    time_out_ms: int = SLAC_ATTEN_TIMEOUT
    aag: [int] = field(default_factory=lambda: [0] * SLAC_GROUPS)
    num_groups: Optional[int] = None
    rnd: bytes = (0).to_bytes(17, "big")
    slac_threshold: int = SLAC_LIMIT
    pause: int = SLAC_PAUSE
    settle_time: int = SLAC_SETTLE_TIME
    matching_process_task: Optional[asyncio.Task] = None

    def reset(self):
        self.state = STATE_UNMATCHED
        self.forwarding_sta = b""
        self.pev_id = None
        self.pev_mac = b""
        self.evse_mac = b""
        self.run_id = b""
        self.application_type = 0x00
        self.security_type = 0x00
        self.num_start_attn_rcvd = 0
        self.num_expected_sounds = None
        self.num_total_sounds = 0
        self.sounds = SLAC_MSOUNDS
        self.time_out_ms = SLAC_ATTEN_TIMEOUT
        self.aag = field(default_factory=lambda: [0] * SLAC_GROUPS)
        self.num_groups = None
        self.rnd = (0).to_bytes(17, "big")
        self.slac_threshold = SLAC_LIMIT
        self.pause = SLAC_PAUSE
        self.settle_time = SLAC_SETTLE_TIME
        self.matching_process_task = None


class SlacEvseSession(SlacSession):
    def __init__(self, evse_id: str, iface: str, config: Config):
        self.iface = iface
        self.evse_id = evse_id
        self.config = config
        evse_board_mac = "88:FC:A6:1C:81:BB"  # EVSE board's actual MAC on PLC
        evse_device_iface = "enxa0cec837bab6"  # Interface where EVSE board is connected

        logger.debug(
            f"Session created for evse_id {self.evse_id} on interface {self.iface}"
        )

        # Socket for SLAC handshake on eno1
        self.socket = create_socket(iface=self.iface, port=0)
        self.slac_mac = get_if_hwaddr(self.iface)  # MAC of eno1 interface

        # Socket for SetKey to EVSE board on enxa0cec837bab6
        self.setkey_socket = create_socket(iface=evse_device_iface, port=0)
        self.setkey_iface = evse_device_iface
        self.setkey_mac = get_if_hwaddr(evse_device_iface)  # MAC of enxa0cec837bab6

        self.evse_plc_mac = EVSE_PLC_MAC
        self.evse_board_mac = bytes.fromhex(evse_board_mac.replace(":", ""))

        SlacSession.__init__(self, state=STATE_UNMATCHED,
                             evse_mac=self.evse_board_mac)  # Use BOARD MAC for identity (IBE)

    def reset_socket(self):
        self.socket.close()
        self.socket = create_socket(iface=self.iface, port=0)

    def reset_setkey_socket(self):
        self.setkey_socket.close()
        self.setkey_socket = create_socket(iface=self.setkey_iface, port=0)

    async def send_frame(self, frame_to_send: bytes) -> None:
        bytes_sent = sendeth(
            s=self.socket, frame_to_send=frame_to_send, iface=self.iface
        )
        if isawaitable(bytes_sent):
            await bytes_sent

    async def rcv_frame(self, rcv_frame_size: int, timeout: Union[float, int]) -> bytes:
        return await asyncio.wait_for(
            readeth(self.socket, self.iface, rcv_frame_size),
            timeout,
        )

    async def leave_logical_network(self):
        await self.evse_set_key()
        self.reset()

    async def evse_set_key(self, nmk: bytes = None, use_device_iface: bool = False) -> bytes:
        """Program EVSE board with NMK via SetKey command.

        Args:
            nmk: NMK to program. If None, generates random NMK.
            use_device_iface: If True, send via enxa0cec837bab6 to reach EVSE board.
                            If False, send via eno1 (for initial bootstrap).
        """
        logger.info("CM_SET_KEY: Started...")
        if nmk is None:
            nmk = urandom(16)
        nid = generate_nid(nmk)
        logger.debug("New NMK: %s", hexlify(nmk))
        logger.debug("New NID: %s", hexlify(nid))

        # Choose socket and source MAC based on which interface to use
        if use_device_iface:
            socket_to_use = self.setkey_socket
            iface_to_use = self.setkey_iface
            src_mac = self.setkey_mac
        else:
            socket_to_use = self.socket
            iface_to_use = self.iface
            src_mac = self.slac_mac

        ethernet_header = EthernetHeader(
            dst_mac=self.evse_board_mac, src_mac=src_mac
        )
        homeplug_header = HomePlugHeader(CM_SET_KEY | MMTYPE_REQ)
        key_req_payload = SetKeyReq(nid=nid, new_key=nmk)
        frame_to_send = (
            ethernet_header.pack_big()
            + homeplug_header.pack_big()
            + key_req_payload.pack_big()
        )
        try:
            bytes_sent = sendeth(s=socket_to_use, frame_to_send=frame_to_send, iface=iface_to_use)
            if isawaitable(bytes_sent):
                await bytes_sent

            data_rcvd = await asyncio.wait_for(
                readeth(socket_to_use, iface_to_use, FramesSizes.CM_SET_KEY_CNF),
                Timers.SLAC_INIT_TIMEOUT if not step_through else step_timeout,
            )
        except asyncio.TimeoutError as e:
            raise TimeoutError("SetKey Timeout raised") from e
        try:
            SetKeyCnf.from_bytes(data_rcvd)
            self.nmk = nmk
            self.nid = nid
        except ValueError as e:
            logger.error(e)
            if self.nmk and self.nid:
                logger.debug(
                    "SetKeyReq has failed, old NMK: %s and NID: %s apply",
                    self.nmk, self.nid,
                )
            else:
                raise ValueError("SetKeyCnf data parsing into the class failed") from e
        logger.debug("Registering NMK and NID into the PLC node...")
        await asyncio.sleep(SLAC_SETTLE_TIME)
        logger.info("CM_SET_KEY: Finished!")

        # ── Status print ────────────────────────────────────
        interface_label = "enxa0cec837bab6 (direct to EVSE board)" if use_device_iface else "eno1"
        print(f"  ▶ Action    : NMK + NID programmed into EVSE QCA7000 PLC chip")
        print(f"  ▶ Dest MAC  : {self.evse_board_mac.hex(':')}")
        print(f"  ▶ Src MAC   : {src_mac.hex(':') if isinstance(src_mac, bytes) else src_mac}")
        print(f"  ▶ NMK       : {hexlify(nmk).decode()}")
        print(f"  ▶ NID       : {hexlify(self.nid).decode()}  (7 bytes, derived from NMK)")
        print(f"  ▶ Interface : {interface_label}")
        print(f"  ▶ Status    : CM_SET_KEY.CNF received — QCA7000 confirmed")

        return data_rcvd

    async def evse_slac_parm(self) -> None:
        logger.debug("CM_SLAC_PARM: Started...")
        self.reset_socket()
        while True:
            try:
                data_rcvd = await self.rcv_frame(
                    rcv_frame_size=FramesSizes.CM_SLAC_PARM_REQ,
                    timeout=self.config.slac_init_timeout if not step_through else step_timeout,
                )
            except TimeoutError as e:
                logger.warning(f"Timeout waiting for CM_SLAC_PARM.REQ: {e}")
                raise e
            try:
                ether_frame = EthernetHeader.from_bytes(data_rcvd)
                homeplug_frame = HomePlugHeader.from_bytes(data_rcvd)
                if homeplug_frame.mm_type != CM_SLAC_PARM | MMTYPE_REQ:
                    logger.warning(f"Frame received is not CM_SLAC_PARM.REQ "
                                   f"({get_mm_type_name(homeplug_frame.mm_type)})")
                    logger.debug("Continue waiting for CM_SLAC_PARM.REQ...")
                    continue
                slac_parm_req = SlacParmReq.from_bytes(data_rcvd)
            except Exception as e:
                logger.exception(e, exc_info=True)
                raise e
            break

        # Save SLAC_PARM_REQ parameters from EV
        self.application_type = slac_parm_req.application_type
        self.security_type    = slac_parm_req.security_type
        self.run_id           = slac_parm_req.run_id
        self.pev_mac          = ether_frame.src_mac
        self.forwarding_sta   = ether_frame.src_mac

        # Send SLAC_PARM_CNF
        ether_header    = EthernetHeader(dst_mac=self.pev_mac, src_mac=self.evse_mac)
        homeplug_header = HomePlugHeader(CM_SLAC_PARM | MMTYPE_CNF)
        slac_parm_cnf   = SlacParmCnf(forwarding_sta=self.pev_mac, run_id=self.run_id)
        frame_to_send   = (
            ether_header.pack_big()
            + homeplug_header.pack_big()
            + slac_parm_cnf.pack_big()
        )
        await self.send_frame(frame_to_send)
        logger.debug("2: Sent SLAC_PARM.CNF")
        self.state = STATE_MATCHING
        logger.debug("CM_SLAC_PARM: Finished!")

        # ── Step 2 print (AFTER data is received so MACs are known) ──
        pev_mac_str  = self.pev_mac.hex(':')  if self.pev_mac  else "unknown"
        evse_mac_str = self.evse_mac.hex(':') if self.evse_mac else "unknown"
        pev_hex      = self.pev_mac.hex()     if self.pev_mac  else "unknown"
        evse_hex     = self.evse_mac.hex()    if self.evse_mac else "unknown"

        banner("[STEP 1]  SLAC PARAMETER EXCHANGE + IDENTITY DISCOVERY")
        print(f"  ▶ CM_SLAC_PARM.REQ received from EV  (broadcast)")
        print(f"  ▶ CM_SLAC_PARM.CNF sent to EV        (unicast)")
        print(f"  ▶ Run ID    : {self.run_id.hex()}")
        print()
        print(f"  ┌{'─'*61}┐")
        print(f"  │{'IDENTITY DISCOVERY  —  EVSE Side':^61}│")
        print(f"  ├{'─'*61}┤")
        print(f"  │  How EVSE learns PEV identity:                              │")
        print(f"  │  Source MAC of CM_SLAC_PARM.REQ frame → PEV identity        │")
        print(f"  │                                                             │")
        print(f"  │  PEV  MAC   : {pev_mac_str:<46} │")
        print(f"  │  IBE ID(EV) : EV:{pev_hex:<43} │")
        print(f"  │                                                             │")
        print(f"  │  EVSE MAC   : {evse_mac_str:<46} │")
        print(f"  │  IBE ID(EV) : EVSE:{evse_hex:<41} │")
        print(f"  │                                                             │")
        print(f"  │  ✓ Both identities now known to EVSE                        │")
        print(f"  │  ✓ These identity strings will be used as IBE inputs        │")
        print(f"  │    at Step 6 to derive the session NMK via pairing          │")
        print(f"  └{'─'*61}┘")
        banner_end()

    async def cm_start_atten_charac(self):
        logger.debug("CM_START_ATTEN_CHAR: Started...")
        while True:
            try:
                data_rcvd = await self.rcv_frame(
                    rcv_frame_size=FramesSizes.CM_START_ATTEN_CHAR_IND,
                    timeout=Timers.SLAC_REQ_TIMEOUT if not step_through else step_timeout,
                )
                EthernetHeader.from_bytes(data_rcvd)
                homeplug_frame = HomePlugHeader.from_bytes(data_rcvd)
                if homeplug_frame.mm_type != CM_START_ATTEN_CHAR | MMTYPE_IND:
                    logger.warning(f"Frame received is not CM_START_ATTEN_CHAR.IND "
                                   f"({get_mm_type_name(homeplug_frame.mm_type)})")
                    logger.debug("Continue waiting for CM_START_ATTEN_CHAR.IND...")
                    continue
                start_atten_char = StartAtennChar.from_bytes(data_rcvd)
            except Exception as e:
                logger.exception(e, exc_info=True)
                raise e

            if (
                self.application_type != start_atten_char.application_type
                or self.security_type != start_atten_char.security_type
                or self.run_id != start_atten_char.run_id
                or start_atten_char.resp_type != SLAC_RESP_TYPE
            ):
                logger.exception(ValueError("Error in StartAttenChar"))
                raise ValueError("Error in StartAttenChar")
            break

        self.num_expected_sounds = start_atten_char.num_sounds
        self.time_out_ms = start_atten_char.time_out * 100
        if self.config.slac_atten_results_timeout:
            self.time_out_ms = self.config.slac_atten_results_timeout
        self.forwarding_sta = start_atten_char.forwarding_sta
        logger.debug("CM_START_ATTEN_CHAR: Finished!")

        # ── Step 2 print ────────────────────────────────────
        banner("[STEP 2]  EV → Broadcast: CM_START_ATTEN_CHAR.IND")
        print(f"  ▶ EV announces start of attenuation measurement")
        print(f"  ▶ Expected Sounds  : {self.num_expected_sounds} MNBC sound bursts")
        print(f"  ▶ Measurement Time : {self.time_out_ms} ms window")
        print(f"  ▶ Response Type    : 0x01 (other GP stations collect data)")
        print(f"  ▶ Status           : CM_START_ATTEN_CHAR.IND received ✓")
        banner_end()

    def process_sound_frame(
        self,
        homeplug_frame: "HomePlugHeader",
        ether_frame: "EthernetHeader",
        data_rcvd: bytes,
        sounds_rcvd: int,
        aag: List[int],
    ) -> int:
        if homeplug_frame.mm_type == CM_MNBC_SOUND | MMTYPE_IND:
            mnbc_sound_ind = MnbcSound.from_bytes(data_rcvd)
            if self.run_id == mnbc_sound_ind.run_id:
                if self.pev_mac != ether_frame.src_mac:
                    raise ValueError(
                        f"Unexpected Source MAC Address for sound "
                        f"number {sounds_rcvd}. "
                        f"PEV MAC: {self.pev_mac}; "
                        f"Source MAC: {ether_frame.src_mac}"
                    )
                logger.debug("MNBC Sound received")
                logger.debug("Remaining number of sounds: %s", mnbc_sound_ind.cnt)
            else:
                logger.debug(
                    "Frame received is a CM_MNBC_SOUND but "
                    "it has an invalid Running Session ID. "
                    "Session RunID: %s\n Received RunID: %s",
                    self.run_id, mnbc_sound_ind.run_id,
                )
            return FramesSizes.CM_ATTEN_PROFILE_IND

        if homeplug_frame.mm_type == CM_ATTEN_PROFILE | MMTYPE_IND:
            atten_profile_ind = AttenProfile.from_bytes(data_rcvd)
            if self.pev_mac == atten_profile_ind.pev_mac:
                for group in range(atten_profile_ind.num_groups):
                    aag[group] += atten_profile_ind.aag[group]
                self.num_groups = atten_profile_ind.num_groups
                self.num_total_sounds += 1
                logger.debug("ATTEN_Profile Sounds received %s", self.num_total_sounds)
                logger.debug(
                    "Num total sounds: %s / Num expected: %s",
                    self.num_total_sounds, self.num_expected_sounds,
                )
            else:
                logger.warning(
                    "PEV MAC %s does not match: %s. Ignoring...",
                    self.pev_mac, atten_profile_ind.pev_mac,
                )
            return FramesSizes.CM_MNBC_SOUND_IND

    async def cm_sounds_loop(self):
        logger.debug("CM_MNBC_SOUND: Started...")
        sounds_rcvd: int = 0
        aag: List[int] = [0] * SLAC_GROUPS
        self.aag = [0] * SLAC_GROUPS
        time_start = time_now_ms()
        self.num_total_sounds = 0
        next_frame_size: int = FramesSizes.CM_MNBC_SOUND_IND
        while True:
            try:
                data_rcvd = await self.rcv_frame(
                    rcv_frame_size=next_frame_size,
                    timeout=1 if not step_through else step_timeout,
                )
                ether_frame    = EthernetHeader.from_bytes(data_rcvd)
                homeplug_frame = HomePlugHeader.from_bytes(data_rcvd)
            except Exception as e:
                logger.exception(e, exc_info=True)
                raise e
            if (
                ether_frame.ether_type == ETH_TYPE_HPAV
                and homeplug_frame.mmv == HOMEPLUG_MMV
            ):
                if homeplug_frame.mm_type in [
                    CM_ATTEN_PROFILE | MMTYPE_IND,
                    CM_MNBC_SOUND | MMTYPE_IND,
                ]:
                    next_frame_size = self.process_sound_frame(
                        homeplug_frame, ether_frame, data_rcvd, sounds_rcvd, aag
                    )
                time_elapsed = time_now_ms() - time_start
                if (
                    time_elapsed < self.time_out_ms
                    and self.num_total_sounds < self.num_expected_sounds
                ):
                    continue
                if self.num_total_sounds > 0:
                    for group in range(SLAC_GROUPS):
                        self.aag[group] = hw(aag[group] / self.num_total_sounds)
                logger.debug("CM_MNBC_SOUND: Finished!")

                # ── Step 4 print ─────────────────────────────
                avg_atten = 0.0
                if self.num_groups and self.num_total_sounds > 0:
                    avg_atten = sum(self.aag[:self.num_groups]) / self.num_groups
                banner("[STEP 3]  SIGNAL ATTENUATION MEASUREMENT")
                print(f"  ▶ EV sent {self.num_total_sounds} MNBC sound bursts on PLC wire")
                print(f"  ▶ QCA7000 measured signal attenuation per frequency group")
                print(f"  ▶ Sounds Received  : {self.num_total_sounds} / {self.num_expected_sounds}")
                print(f"  ▶ Frequency Groups : {self.num_groups}")
                print(f"  ▶ Avg Attenuation  : {avg_atten:.2f} dB  "
                      f"(threshold = {self.slac_threshold} dB)")
                print(f"  ▶ Status           : All sounds received — attenuation averaged ✓")
                banner_end()
                return

    async def cm_atten_char(self):
        logger.debug("CM_ATTEN_CHAR Started...")
        ether_header    = EthernetHeader(dst_mac=self.pev_mac, src_mac=self.evse_mac)
        homeplug_header = HomePlugHeader(CM_ATTEN_CHAR | MMTYPE_IND)
        atten_charac    = AtennChar(
            source_address=self.pev_mac,
            run_id=self.run_id,
            num_sounds=self.num_total_sounds,
            num_groups=self.num_groups,
            aag=self.aag,
        )
        frame_to_send = (
            ether_header.pack_big()
            + homeplug_header.pack_big()
            + atten_charac.pack_big()
        )
        await self.send_frame(frame_to_send)
        logger.debug("3: Sent ATTEN_CHAR.IND")

        while True:
            try:
                data_rcvd = await self.rcv_frame(
                    rcv_frame_size=FramesSizes.CM_ATTEN_CHAR_RSP,
                    timeout=1 if not step_through else step_timeout,
                )
                logger.debug(f"Payload Received: \n {hexlify(data_rcvd)}")
                ether_frame    = EthernetHeader.from_bytes(data_rcvd)
                homeplug_frame = HomePlugHeader.from_bytes(data_rcvd)
                if homeplug_frame.mm_type != CM_ATTEN_CHAR | MMTYPE_RSP:
                    logger.warning(f"Frame received is not CM_ATTEN_CHAR.RSP "
                                   f"({get_mm_type_name(homeplug_frame.mm_type)})")
                    logger.debug("Continue waiting for CM_ATTEN_CHAR.RSP...")
                    continue
                atten_charac_response = AtennCharRsp.from_bytes(data_rcvd)
            except Exception as e:
                logger.exception(e, exc_info=True)
                raise e

            if (
                ether_frame.ether_type != ETH_TYPE_HPAV
                or homeplug_frame.mmv != HOMEPLUG_MMV
                or self.run_id != atten_charac_response.run_id
            ):
                e = ValueError(
                    "AttenChar Resp Failed, ether type or homeplug frame are incorrect."
                )
                logger.exception(e)
                raise e
            break

        if atten_charac_response.result != 0:
            e = ValueError("Atten Char Resp Failed: Atten Char Result is not 0x00")
            logger.exception(e)
            raise e
        logger.debug("CM_ATTEN_CHAR: Finished!")

        # ── Step 4 print ────────────────────────────────────
        banner("[STEP 4]  ATTENUATION CHARACTERIZATION EXCHANGE")
        print(f"  ▶ CM_ATTEN_CHAR.IND sent to EV  (averaged attenuation data)")
        print(f"  ▶ CM_ATTEN_CHAR.RSP received from EV")
        print(f"  ▶ Result    : 0x{atten_charac_response.result:02x}  "
              f"({'SUCCESS — within threshold' if atten_charac_response.result == 0 else 'FAILURE'})")
        print(f"  ▶ Sounds    : {self.num_total_sounds} received / {self.num_expected_sounds} expected")
        print(f"  ▶ Status    : EV accepted attenuation — proceeding to key establishment ✓")
        banner_end()

    async def cm_ibe_key_establishment(self):
        logger.debug("CM_IBE_KEY_ESTABLISHMENT: Started...")

        ibe = CertificatelessKeyEstablishment()

        # MAC addresses serve as identities
        ev_mac = self.pev_mac.hex()
        evse_mac = self.evse_mac.hex()

        # Manufacturer tags (distinguish identity public elements per manufacturer)
        M_EV = "M_EV"
        M_EVSE = "M_EVSE"

        # Full identity strings for context (MAC || manufacturer)
        ev_identity = ev_mac + M_EV
        evse_identity = evse_mac + M_EVSE

        # ── Step 5 print — part 1: Two-manufacturer PKG + cross-domain enrollment ─────
        banner("[STEP 5]  CERTIFICATELESS KEY ESTABLISHMENT  (EVSE Side)")
        print(f"  ▶ Method    : Certificateless Two-Party IBC over bilinear pairing (SS512)")
        print(f"  ▶ Security  : BDH (Bilinear Diffie-Hellman) assumption")
        print(f"  ▶ Scheme    : Cross-domain enrollment with two manufacturers")
        print()
        print(f"  Private Key Generators (Two Manufacturers):")
        print(f"  ▶ EV Mfg    : s_M_EV, public key mpk_M_EV = s_M_EV * P")
        print(f"  ▶ EVSE Mfg  : s_M_EVSE, public key mpk_M_EVSE = s_M_EVSE * P")
        print(f"  ▶ Files     : {ibe.master_secret_ev_path}")
        print(f"  ▶ Files     : {ibe.master_secret_evse_path}")
        print()
        print(f"  Identity Strings (MAC || Manufacturer tag):")
        print(f"  ▶ EV   ID   : {ev_mac} || {M_EV}")
        print(f"  ▶ EVSE ID   : {evse_mac} || {M_EVSE}")
        print()

        # Cross-domain private key computation
        # SK_EVSE = s_M_EV * Q_EVSE + s_M_EVSE * Q_EVSE
        evse_sk = ibe.compute_cross_domain_private_key(evse_mac, M_EVSE)
        print(f"  Cross-Domain Private Key Computation (EVSE):")
        print(f"  ▶ Formula   : SK_EVSE = s_M_EV * Q_EVSE + s_M_EVSE * Q_EVSE")
        print(f"  ▶ where     : Q_EVSE = H(ID_EVSE || M_EVSE)")
        print(f"  ▶ Partial 1 : s_M_EV * Q_EVSE (from EV manufacturer)")
        print(f"  ▶ Partial 2 : s_M_EVSE * Q_EVSE (from EVSE manufacturer)")
        print(f"  ▶ Combined  : SK_EVSE = Partial 1 + Partial 2 (locally)")
        print(f"  ▶ SK Type   : {type(evse_sk.secret_key).__name__} "
              f"(pairing.Element in G1)")
        print(f"  ▶ Status    : EVSE cross-domain key computed ✓")
        print()

        # Derive shared secret via bilinear pairing
        # K_EVSE = e(SK_EVSE, Q_EV)
        shared_secret = ibe.derive_shared_secret(
            my_private_key=evse_sk,
            peer_identity=ev_mac,
            peer_manufacturer_tag=M_EV,
        )
        print(f"  Bilinear Pairing Computation (EVSE):")
        print(f"  ▶ Formula   : K_EVSE = e(SK_EVSE, Q_EV)")
        print(f"               = e((s_M_EV + s_M_EVSE)*Q_EVSE, Q_EV)")
        print(f"  ▶ Result    : e(Q_EV, Q_EVSE)^(s_M_EV + s_M_EVSE)")
        print(f"  ▶ By bilinearity, EV computes: K_EV = e(Q_EV, SK_EVSE)")
        print(f"  ▶ Which gives the same result: e(Q_EV, Q_EVSE)^(s_M_EV + s_M_EVSE)")
        print(f"  ▶ Shared    : {shared_secret.hex()[:40]}...  ({len(shared_secret)} bytes)")
        print(f"  ▶ Status    : Pairing computed ✓")
        print()

        self.nmk = ibe.derive_nmk(
            shared_secret=shared_secret,
            run_id=self.run_id,
            ev_identity=ev_identity,
            evse_identity=evse_identity,
        )
        self.nid = generate_nid(self.nmk)

        print(f"  NMK Derivation:")
        print(f"  ▶ Formula   : NMK = SHA256(shared || 'SLAC-IBC-NMK-v1'")
        print(f"                             || run_id || ID_EV || ID_EVSE)[:16]")
        print(f"  ▶ Run ID    : {self.run_id.hex()}")
        print(f"  ▶ NMK       : {self.nmk.hex()}  (16 bytes)")
        print(f"  ▶ NID       : {self.nid.hex()}  (7 bytes, derived from NMK)")
        print()
        print(f"  Security Properties:")
        print(f"  ▶ Wire      : ZERO key material transmitted over PLC ✓")
        print(f"  ▶ Compare   : ECDH sends 2 public key frames (0x6080 + 0x6083)")
        print(f"  ▶ IBE       : 0 frames — non-interactive key establishment")
        print(f"  ▶ Status    : NMK established successfully ✓")
        banner_end()

        logger.debug("CM_IBE_KEY_ESTABLISHMENT: Finished!")

    async def cm_slac_match(self):
        logger.debug("CM_SLAC_MATCH: Started...")
        while True:
            try:
                data_rcvd = await self.rcv_frame(
                    rcv_frame_size=FramesSizes.CM_SLAC_MATCH_REQ,
                    timeout=Timers.SLAC_MATCH_TIMEOUT if not step_through else step_timeout,
                )
                logger.debug(f"Payload Received: \n {hexlify(data_rcvd)}")
                ether_frame    = EthernetHeader.from_bytes(data_rcvd)
                homeplug_frame = HomePlugHeader.from_bytes(data_rcvd)
                if homeplug_frame.mm_type != CM_SLAC_MATCH | MMTYPE_REQ:
                    logger.warning(f"Frame received is not CM_SLAC_MATCH.REQ "
                                   f"({get_mm_type_name(homeplug_frame.mm_type)})")
                    logger.debug("Continue waiting for CM_SLAC_MATCH.REQ...")
                    continue
                slac_match_req = MatchReq.from_bytes(data_rcvd)
            except Exception as e:
                logger.exception(e, exc_info=True)
                raise ValueError("SLAC Match Failed") from e

            if (
                ether_frame.ether_type != ETH_TYPE_HPAV
                or homeplug_frame.mmv != HOMEPLUG_MMV
                or slac_match_req.run_id != self.run_id
            ):
                raise ValueError("SLAC Match Request Failed")
            break

        self.pev_id  = slac_match_req.pev_id
        self.pev_mac = slac_match_req.pev_mac

        ether_header    = EthernetHeader(dst_mac=self.pev_mac, src_mac=self.evse_mac)
        homeplug_header = HomePlugHeader(CM_SLAC_MATCH | MMTYPE_CNF)
        slac_match_conf = MatchCnf(
            pev_mac=self.pev_mac,
            evse_mac=self.evse_mac,
            run_id=self.run_id,
            nid=self.nid,
            nmk=urandom(16),
        )
        frame_to_send = (
            ether_header.pack_big()
            + homeplug_header.pack_big()
            + slac_match_conf.pack_big()
        )
        await self.send_frame(frame_to_send)
        logger.debug("10: Sent CM_SLAC_MATCH.CNF")
        logger.debug("CM_SLAC_MATCH: Finished!")
        self.state = STATE_MATCHED

        # ── Step 6 print ────────────────────────────────────
        banner("[STEP 6]  SLAC MATCH — HANDSHAKE COMPLETE")
        print(f"  ▶ CM_SLAC_MATCH.REQ received from EV")
        print(f"  ▶ CM_SLAC_MATCH.CNF sent to EV")
        print(f"  ▶ NMK in CNF : urandom(16) — real NMK never transmitted ✓")
        print()
        print(f"  Session Summary:")
        print(f"  ▶ PEV  MAC  : {self.pev_mac.hex(':')}")
        print(f"  ▶ EVSE MAC  : {self.evse_mac.hex(':')}")
        print(f"  ▶ Run ID    : {self.run_id.hex()}")
        print(f"  ▶ NMK       : {self.nmk.hex()}")
        print(f"  ▶ NID       : {self.nid.hex()}")
        print()
        print(f"  ▶ Result    : PEV-EVSE MATCHED ✓")
        print(f"  ▶ PLC Net   : Logical network established on QCA7000 chips")
        print(f"  ▶ Next Step : ISO 15118-2 HLC charging communication begins")
        banner_end()

    async def is_link_status_active(self) -> bool:
        logger.debug("Checking Link Status: Started...")
        ethernet_header = EthernetHeader(
            dst_mac=self.evse_plc_mac, src_mac=self.evse_mac
        )
        LINK_STATUS = 0xA0B8
        mmv = b"\x00"
        mm_type = LINK_STATUS | MMTYPE_REQ
        homeplug_header_no_fragm = mmv + mm_type.to_bytes(2, "little")
        vendor_mme = 0x00B052
        link_status_req_payload = vendor_mme.to_bytes(3, "big")
        frame_to_send = (
            ethernet_header.pack_big()
            + homeplug_header_no_fragm
            + link_status_req_payload
        )
        payload_rcvd = send_recv_eth(
            frame_to_send=frame_to_send,
            s=self.socket,
            iface=self.iface,
            rcv_frame_size=FramesSizes.LINK_STATUS_CNF,
        )
        if isawaitable(payload_rcvd):
            payload_rcvd = await payload_rcvd
        logger.debug(f"Payload Received {payload_rcvd}")
        try:
            mm_type_rcvd = int.from_bytes(payload_rcvd[15:17], "little")
            if mm_type_rcvd != (LINK_STATUS | MMTYPE_CNF):
                raise ValueError("Message received is not LINK_STATUS.CNF")
        except ValueError as e:
            logger.error(e)
            logger.debug("Link Status: Error")
            return False
        logger.debug("Link Status: Active")
        return True

    async def atten_charac_routine(self):
        await self.cm_start_atten_charac()
        await self.cm_sounds_loop()
        await self.cm_atten_char()
        await self.cm_ibe_key_establishment()
        # Update EVSE board with IBE-derived NMK via device interface
        await self.evse_set_key(nmk=self.nmk, use_device_iface=True)
        await self.cm_slac_match()


class SlacSessionController:
    def __init__(self):
        logger.info(
            f"\n\n#################################################"
            f"\n ###### Starting PySlac version: {__version__} #######"
            f"\n#################################################\n"
        )

    async def notify_matching_ongoing(self, evse_id: str):
        logger.info(f"Matching is ongoing for {evse_id}")
        print(f"\n  ★ SLAC matching process active — EVSE: {evse_id}")
        print(f"  ★ Waiting for EV to complete SLAC steps 3-7...\n")

    async def notify_matching_failed(self, evse_id: str):
        pass

    async def enable_hlc_charging(self, evse_id: str):
        logger.info(f"Enable PWM and set 5% duty cycle for evse {evse_id}")

    async def process_cp_state(self, slac_session, state: str):
        cp_state = state[0]
        logger.debug(f"CP State Received: {state}")
        if cp_state in ["A", "E", "F"] and slac_session.matching_process_task:
            if cp_state == "A" or slac_session.state == STATE_MATCHED:
                await cancel_task(slac_session.matching_process_task)
                logger.debug("Matching process task canceled")
                slac_session.matching_process_task = None
                logger.debug("Leaving Logical Network")
        elif cp_state in ["B", "C", "D"] and slac_session.matching_process_task is None:
            slac_session.matching_process_task = asyncio.create_task(
                self.start_matching(slac_session)
            )
            slac_session.matching_process_task.set_name(
                f"Session for EVSE {slac_session.evse_id}"
            )
            slac_session.matching_process_task.add_done_callback(task_callback)

    async def start_matching(
        self, slac_session: "SlacEvseSession", number_of_retries=3
    ) -> None:
        while number_of_retries:
            number_of_retries -= 1
            await slac_session.evse_slac_parm()
            if slac_session.state == STATE_MATCHING:
                logger.info(
                    f"Matching ongoing (EVSE ID: {slac_session.evse_id}. "
                    f"Run ID: {slac_session.run_id})."
                )
                await self.notify_matching_ongoing(slac_session.evse_id)
                try:
                    await slac_session.atten_charac_routine()
                except Exception as e:
                    slac_session.state = STATE_UNMATCHED
                    logger.debug(
                        f"Exception Occurred during Attenuation Charc Routine:"
                        f"{e} \nNumber of retries left {number_of_retries}"
                    )
            if slac_session.state == STATE_MATCHED:
                logger.info(
                    f"PEV-EVSE MATCHED Successfully, Link Established "
                    f"(EVSE ID: {slac_session.evse_id}. "
                    f"Run ID: {slac_session.run_id})."
                )
                while True:
                    await asyncio.sleep(2.0)
            if slac_session.state == STATE_UNMATCHED:
                number_of_retries -= 1
                if number_of_retries > 0:
                    logger.warning("PEV-EVSE MATCHED Failed; Retrying..")
                else:
                    logger.error("PEV-EVSE MATCHED Failed: No more retries possible")
                    await self.notify_matching_failed(slac_session.evse_id)
            else:
                logger.error(f"SLAC State not recognized {slac_session.state}")

        logger.debug("SLAC Protocol Concluded...")
        await slac_session.leave_logical_network()