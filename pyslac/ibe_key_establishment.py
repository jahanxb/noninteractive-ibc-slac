from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Tuple
from charm.toolbox.pairinggroup import PairingGroup, G1, pair

@dataclass
class IBEPrivateKey:
    identity: str
    secret_key: object

class IBEKeyEstablishment:
    def __init__(
        self,
        group_name: str = "SS512",
        master_secret_file: str = "/opt/VehicleSecProject/slac_dylan_ddh/pyslac/ibe_master_secret.bin",
        generator_file: str = "/opt/VehicleSecProject/slac_dylan_ddh/pyslac/ibe_generator.bin",
    ) -> None:
        self.group_name = group_name
        self.group = PairingGroup(group_name)
        self.master_secret_path = Path(master_secret_file)
        self.generator_path = Path(generator_file)

        if self.master_secret_path.exists() and self.generator_path.exists():
            self.master_secret = self.group.deserialize(
                self.master_secret_path.read_bytes()
            )
            self.generator = self.group.deserialize(
                self.generator_path.read_bytes()
            )
        else:
            self.master_secret = self.group.random()
            self.generator = self.group.random(G1)
            self.master_secret_path.write_bytes(
                self.group.serialize(self.master_secret)
            )
            self.generator_path.write_bytes(
                self.group.serialize(self.generator)
            )

        self.public_key = self.master_secret * self.generator

    def identity_public_key(self, identity: str):
        if not identity:
            raise ValueError("identity must be non-empty")
        return self.group.hash(identity.encode("utf-8"), G1)

    def extract_private_key(self, identity: str) -> IBEPrivateKey:
        q_id = self.identity_public_key(identity)
        sk_id = self.master_secret * q_id
        return IBEPrivateKey(identity=identity, secret_key=sk_id)

    def derive_shared_secret(
        self,
        my_private_key: IBEPrivateKey,
        peer_identity: str,
    ) -> bytes:
        peer_public_key = self.identity_public_key(peer_identity)
        shared_element = pair(my_private_key.secret_key, peer_public_key)
        return self.group.serialize(shared_element)

    @staticmethod
    def derive_nmk(
        shared_secret: bytes,
        run_id: bytes,
        ev_identity: str,
        evse_identity: str,
    ) -> bytes:
        context = (
            b"SLAC-IBE-NMK-v1"
            + b"|"
            + run_id
            + b"|"
            + ev_identity.encode("utf-8")
            + b"|"
            + evse_identity.encode("utf-8")
        )
        return sha256(shared_secret + context).digest()[:16]

if __name__ == "__main__":
    ibe = IBEKeyEstablishment()
    ev_identity   = "EV:88fca61c81c2"
    evse_identity = "EVSE:88fca61c81bb"
    run_id = bytes(8)

    ev_sk   = ibe.extract_private_key(ev_identity)
    evse_sk = ibe.extract_private_key(evse_identity)

    ev_shared   = ibe.derive_shared_secret(ev_sk,   evse_identity)
    evse_shared = ibe.derive_shared_secret(evse_sk, ev_identity)

    ev_nmk   = ibe.derive_nmk(ev_shared,   run_id, ev_identity, evse_identity)
    evse_nmk = ibe.derive_nmk(evse_shared, run_id, ev_identity, evse_identity)

    print("EV NMK:  ", ev_nmk.hex())
    print("EVSE NMK:", evse_nmk.hex())
    print("Match:   ", ev_nmk == evse_nmk)
