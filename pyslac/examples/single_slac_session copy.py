from pyslac.utils import is_distro_linux

if not is_distro_linux():
    raise EnvironmentError("Non-Linux systems are not supported")

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


class SlacHandler(SlacSessionController):
    def __init__(self, slac_config: Config):
        SlacSessionController.__init__(self)
        self.slac_config = slac_config
        self.running_sessions: List["SlacEvseSession"] = []

    async def notify_matching_ongoing(self, evse_id: str):
        logger.info(f"Matching is ongoing for {evse_id}")
        print(f"\n  ★ SLAC matching process started for EVSE: {evse_id}")
        print(f"  ★ Waiting for EV to complete SLAC handshake...\n")

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

        # Add this banner
        print("\n" + "="*65)
        print("  SLAC + IBE PROTOCOL SESSION STARTING (EVSE)")
        print("="*65)
        print(f"  ▶ EVSE ID    : {evse_id}")
        print(f"  ▶ Interface  : {network_interface}")
        print(f"  ▶ Protocol   : ISO 15118-3 SLAC + IBE Key Establishment")
        print(f"  ▶ IBE Scheme : Boneh-Franklin over SS512 pairing group")
        print(f"  ▶ Hardware   : devolo dLAN Green PHY QCA7000")
        print("="*65 + "\n")

    async def enable_hlc_and_trigger_slac(self, session):
        await self.enable_hlc_charging(session.evse_id)

        print("\n" + "="*65)
        print("  CONTROL PILOT STATE MACHINE")
        print("="*65)

        await self.process_cp_state(session, "B")
        print(f"  ▶ CP State B : EV connected — SLAC listening window open")

        await asyncio.sleep(2)

        await self.process_cp_state(session, "C")
        print(f"  ▶ CP State C : EV requests energy — SLAC matching window active (60s)")
        print("="*65 + "\n")

        await asyncio.sleep(20 if not step_through else 60)

        await self.process_cp_state(session, "A")
        print(f"\n  ▶ CP State A : Session ended — logical network leaving")


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