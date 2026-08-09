from pyslac.utils import is_distro_linux

if not is_distro_linux():
    raise EnvironmentError("Non-Linux systems are not supported")

#filename: single_slac_session.py

import asyncio
import json
import logging
import os
from typing import List, Optional

from pyslac.environment import Config
from pyslac.session import SlacEvseSession, SlacSessionController
from pyslac.utils import wait_for_tasks

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__file__)

step_through = True

W = 67

def banner(title):
    print("\n" + "="*W)
    print(f"  {title}")
    print("="*W)

def banner_end():
    print("="*W + "\n")


class SlacHandler(SlacSessionController):
    def __init__(self, slac_config: Config):
        SlacSessionController.__init__(self)
        self.slac_config = slac_config
        self.running_sessions: List["SlacEvseSession"] = []

    async def notify_matching_ongoing(self, evse_id: str):
        logger.info(f"Matching is ongoing for {evse_id}")
        print(f"\n  ★ SLAC matching process active — EVSE: {evse_id}")
        print(f"  ★ Waiting for EV to complete SLAC steps 3-7...\n")

    async def enable_hlc_charging(self, evse_id: str):
        logger.info(f"Enable PWM and set 5% duty cycle for evse {evse_id}")

    async def start(self, cs_config: dict):
        if cs_config["number_of_evses"] < 1 or (
            len(cs_config["parameters"]) != cs_config["number_of_evses"]
        ):
            raise AttributeError("Number of evses provided is invalid.")

        evse_params: dict = cs_config["parameters"][0]
        evse_id: str = evse_params["evse_id"]
        network_interface: str = evse_params["network_interface"]

        # ── Session start banner ─────────────────────────────
        banner("SLAC + IBE PROTOCOL SESSION STARTING  (EVSE Side)")
        print(f"  ▶ EVSE ID    : {evse_id}")
        print(f"  ▶ Interface  : {network_interface}")
        print(f"  ▶ EVSE MAC   : 88:fc:a6:1c:81:bb  (Board2 devolo QCA7000)")
        print(f"  ▶ Protocol   : ISO 15118-3 SLAC + IBE Key Establishment")
        print(f"  ▶ IBE Scheme : Boneh-Franklin over SS512 pairing group")
        print(f"  ▶ Hardware   : devolo dLAN Green PHY Eval Board II")
        print(f"  ▶ PLC Chip   : Qualcomm QCA7000")
        banner_end()

        try:
            slac_session = SlacEvseSession(evse_id, network_interface, self.slac_config)
            await slac_session.evse_set_key()  # Initialize EVSE board (will be updated with IBE NMK later)
            self.running_sessions.append(slac_session)
        except (OSError, TimeoutError, ValueError) as e:
            logger.error(
                f"PLC chip initialization failed for "
                f"EVSE {evse_id}, interface "
                f"{network_interface}: {e}. \n"
                f"Please check your settings."
            )
            return

        await self.enable_hlc_and_trigger_slac(self.running_sessions[0])

    async def enable_hlc_and_trigger_slac(self, session):
        await self.enable_hlc_charging(session.evse_id)

        # ── Control Pilot state machine banner ───────────────
        banner("CONTROL PILOT (CP) STATE MACHINE")
        print(f"  ▶ Standard  : SAE J1772 / IEC 61851")
        print(f"  ▶ Purpose   : Simulate EV plug-in and charging request")
        print()

        await self.process_cp_state(session, "B")
        print(f"  ▶ CP State B : EV physically connected")
        print(f"               : SLAC listening window open")
        print(f"               : EVSE waiting for CM_SLAC_PARM.REQ...")

        await asyncio.sleep(2)

        await self.process_cp_state(session, "C")
        print(f"  ▶ CP State C : EV requests energy delivery")
        print(f"               : SLAC matching window active")
        print(f"               : Timeout = {60 if step_through else 20}s")
        banner_end()

        await asyncio.sleep(20 if not step_through else 60)

        await self.process_cp_state(session, "A")

        banner("SESSION ENDED")
        print(f"  ▶ CP State A : EV disconnected")
        print(f"  ▶ Action    : Leaving logical PLC network")
        print(f"  ▶ Status    : Session complete")
        banner_end()


async def main(env_path: Optional[str] = None):
    slac_config = Config()
    slac_config.load_envs(env_path)
    root_dir = os.path.dirname(os.path.abspath(__file__))
    json_file = open(os.path.join(root_dir, "cs_configuration.json"))
    cs_config = json.load(json_file)
    json_file.close()
    slac_handler = SlacHandler(slac_config)
    tasks = [slac_handler.start(cs_config)]
    await wait_for_tasks(tasks)


def run():
    asyncio.run(main())


if __name__ == "__main__":
    run()