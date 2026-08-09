"""
Certificateless Two-Party Key Establishment for SLAC.

Implements the non-interactive Identity-Based Cryptography (IBC) scheme from:
"Demo: Certificateless and Non-Interactive Key Establishment for Secure CCS EV Charging"

Key difference from Boneh-Franklin IBE:
- TWO manufacturers (EV manufacturer and EVSE manufacturer), each with independent master secrets
- Cross-domain enrollment: each node combines partial keys from both manufacturers
- Combined private key: SK_EV = s_M_EV * Q_EV + s_M_EVSE * Q_EV
- Shared secret via pairing: K = e(Q_EV, Q_EVSE)^(s_M_EV + s_M_EVSE)

No additional protocol messages; key derivation is local and non-interactive.
"""

from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Tuple
from charm.toolbox.pairinggroup import PairingGroup, G1, pair


@dataclass
class CertificatelessPrivateKey:
    """Combined private key from both manufacturers' partial keys.

    Attributes:
        identity (str): Identity string (MAC || manufacturer_tag)
        secret_key (pairing element): Combined key SK = s_M1 * Q_ID + s_M2 * Q_ID
    """
    identity: str
    secret_key: object


class CertificatelessKeyEstablishment:
    """Two-party certificateless key establishment with cross-domain enrollment.

    Architecture:
    - Two manufacturers: EV manufacturer (M_EV) and EVSE manufacturer (M_EVSE)
    - Each maintains independent master secret and publishes public key
    - During enrollment, each node receives TWO partial keys (one from each manufacturer)
    - Node combines partial keys locally into a single private key
    - Shared NMK derived via bilinear pairing, no wire traffic for key exchange
    """

    def __init__(
        self,
        group_name: str = "SS512",
        master_secret_ev_file: str = "/home/jack/projects/noninteractive-ibc-slac/ibe_master_secret_ev.bin",
        master_secret_evse_file: str = "/home/jack/projects/noninteractive-ibc-slac/ibe_master_secret_evse.bin",
        generator_file: str = "/home/jack/projects/noninteractive-ibc-slac/ibe_generator.bin",
    ) -> None:
        """Initialize the two-manufacturer certificateless scheme.

        Args:
            group_name: Pairing group name (e.g., "SS512")
            master_secret_ev_file: Path to EV manufacturer's master secret
            master_secret_evse_file: Path to EVSE manufacturer's master secret
            generator_file: Path to generator P (shared by both manufacturers)

        Master secrets are persisted so both nodes use the same PKG material.
        If files don't exist, random secrets are generated and saved.
        """
        self.group_name = group_name
        self.group = PairingGroup(group_name)

        # Paths for master secrets and generator
        self.master_secret_ev_path = Path(master_secret_ev_file)
        self.master_secret_evse_path = Path(master_secret_evse_file)
        self.generator_path = Path(generator_file)

        # ─────────────────────────────────────────────────────────────────────
        # Load or generate: EV Manufacturer's master secret s_M_EV
        # ─────────────────────────────────────────────────────────────────────
        if self.master_secret_ev_path.exists():
            self.s_m_ev = self.group.deserialize(
                self.master_secret_ev_path.read_bytes()
            )
        else:
            self.s_m_ev = self.group.random()
            self.master_secret_ev_path.write_bytes(
                self.group.serialize(self.s_m_ev)
            )

        # ─────────────────────────────────────────────────────────────────────
        # Load or generate: EVSE Manufacturer's master secret s_M_EVSE
        # ─────────────────────────────────────────────────────────────────────
        if self.master_secret_evse_path.exists():
            self.s_m_evse = self.group.deserialize(
                self.master_secret_evse_path.read_bytes()
            )
        else:
            self.s_m_evse = self.group.random()
            self.master_secret_evse_path.write_bytes(
                self.group.serialize(self.s_m_evse)
            )

        # ─────────────────────────────────────────────────────────────────────
        # Load or generate: Generator P (shared between both manufacturers)
        # ─────────────────────────────────────────────────────────────────────
        if self.generator_path.exists():
            self.P = self.group.deserialize(
                self.generator_path.read_bytes()
            )
        else:
            self.P = self.group.random(G1)
            self.generator_path.write_bytes(
                self.group.serialize(self.P)
            )

        # ─────────────────────────────────────────────────────────────────────
        # Compute public keys published by each manufacturer
        # mpk_M_EV = s_M_EV * P
        # mpk_M_EVSE = s_M_EVSE * P
        # ─────────────────────────────────────────────────────────────────────
        self.mpk_m_ev = self.s_m_ev * self.P
        self.mpk_m_evse = self.s_m_evse * self.P

    def identity_public_key(self, identity: str, manufacturer_tag: str) -> object:
        """Compute identity-specific public element Q_ID = H(ID || M).

        EQUATION FROM PAPER:
        ───────────────────
        Q_EV = H(ID_EV || M_EV)      ← Identity public element for EV
        Q_EVSE = H(ID_EVSE || M_EVSE) ← Identity public element for EVSE

        WHERE:
        - H: {0,1}* → G1 (cryptographic hash to group element)
        - ID_EV, ID_EVSE: MAC addresses (identities)
        - M_EV, M_EVSE: Manufacturer tags (distinguishes across domains)
        - G1: First group of bilinear pair (SS512 pairing)

        PURPOSE:
        --------
        Creates identity-bound public elements. These are never secret, and
        every party can compute them from the identity and manufacturer tag.
        Domain separation (|| M_EV vs || M_EVSE) ensures cross-domain security.

        Args:
            identity: The identity string (MAC address)
            manufacturer_tag: Manufacturer identifier ("M_EV" or "M_EVSE")

        Returns:
            Group element Q_ID in G1 (public element bound to identity)

        Cryptographer verification:
        ─────────────────────────
        This implements the public parameter computation from the scheme's
        initialization phase. Verify:
        1. Hash function is deterministic (same input → same output)
        2. Hash maps to G1 (bilinear pairing group element)
        3. Domain separation prevents identity confusion across manufacturers
        """
        if not identity:
            raise ValueError("identity must be non-empty")
        if not manufacturer_tag:
            raise ValueError("manufacturer_tag must be non-empty")

        # EQUATION: Q_ID = H(ID || M)
        # Hash input concatenates identity and manufacturer tag
        input_bytes = identity.encode("utf-8") + manufacturer_tag.encode("utf-8")
        return self.group.hash(input_bytes, G1)

    def compute_cross_domain_private_key(
        self,
        identity: str,
        manufacturer_tag: str,
    ) -> CertificatelessPrivateKey:
        """Compute cross-domain private key via enrollment.

        EQUATIONS FROM PAPER (CROSS-DOMAIN ENROLLMENT):
        ──────────────────────────────────────────────
        For EV node:
            SK_EV = s_M_EV * Q_EV + s_M_EVSE * Q_EV
                  = (s_M_EV + s_M_EVSE) * Q_EV

        For EVSE node:
            SK_EVSE = s_M_EV * Q_EVSE + s_M_EVSE * Q_EVSE
                    = (s_M_EV + s_M_EVSE) * Q_EVSE

        WHERE:
        - s_M_EV, s_M_EVSE: Master secrets of EV and EVSE manufacturers
                            (Private to each manufacturer's PKG)
        - Q_EV = H(ID_EV || M_EV): Identity public element for EV
        - Q_EVSE = H(ID_EVSE || M_EVSE): Identity public element for EVSE
        - *: Scalar multiplication in G1 (elliptic curve group)
        - +: Group addition in G1

        KEY PROPERTY (Non-Interactive Security):
        ────────────────────────────────────────
        Both manufacturers' master secrets are REQUIRED to compute the
        private key. This means:

        1. Neither manufacturer alone can generate valid keys
        2. Cross-domain enrollment ensures mutual trust between manufacturers
        3. Each node's security depends on BOTH manufacturers' PKGs
        4. Attack on one manufacturer's secret breaks both domains

        ENROLLMENT FLOW (Testbed vs Production):
        ─────────────────────────────────────────
        TESTBED (simulated PKGs locally):
            - Both s_M_EV and s_M_EVSE are available locally
            - Node computes: partial_1 = s_M_EV * Q_NODE
            - Node computes: partial_2 = s_M_EVSE * Q_NODE
            - Node combines: SK_NODE = partial_1 + partial_2

        PRODUCTION (distributed PKGs):
            - EV manufacturer's PKG sends: s_M_EV * Q_NODE (over authenticated channel)
            - EVSE manufacturer's PKG sends: s_M_EVSE * Q_NODE (over authenticated channel)
            - Node receives both and combines locally: SK_NODE = partial_1 + partial_2

        Args:
            identity: Node's identity (MAC address)
            manufacturer_tag: Node's manufacturer tag ("M_EV" or "M_EVSE")

        Returns:
            CertificatelessPrivateKey containing combined SK_NODE

        Cryptographer verification:
        ──────────────────────────
        Verify implementation matches:
        1. Both partial keys are computed independently
        2. Addition is performed in the correct group (G1)
        3. Scalar multiplication uses correct elements (s_M_EV/s_M_EVSE with G1)
        4. Result is stored as group element, not integer
        5. Combining partial keys does not reduce security (bilinear assumption)
        """
        # EQUATION: Q_NODE = H(ID_NODE || M_NODE)
        # Get identity public element (deterministic, publicly computable)
        Q_node = self.identity_public_key(identity, manufacturer_tag)

        # EQUATION: partial_key_ev = s_M_EV * Q_NODE
        # First manufacturer's contribution to private key
        # s_M_EV: master secret (scalar), Q_NODE: identity public element (group element)
        # Result: group element representing EV manufacturer's partial key
        partial_key_ev = self.s_m_ev * Q_node

        # EQUATION: partial_key_evse = s_M_EVSE * Q_NODE
        # Second manufacturer's contribution to private key
        # s_M_EVSE: master secret (scalar), Q_NODE: identity public element (group element)
        # Result: group element representing EVSE manufacturer's partial key
        partial_key_evse = self.s_m_evse * Q_node

        # EQUATION: SK_NODE = partial_key_ev + partial_key_evse
        #                   = s_M_EV * Q_NODE + s_M_EVSE * Q_NODE
        # Cross-domain enrollment: combine both manufacturers' contributions
        # Addition is in the additive group G1 (elliptic curve points)
        sk_combined = partial_key_ev + partial_key_evse

        return CertificatelessPrivateKey(identity=identity, secret_key=sk_combined)

    def derive_shared_secret(
        self,
        my_private_key: CertificatelessPrivateKey,
        peer_identity: str,
        peer_manufacturer_tag: str,
    ) -> bytes:
        """Derive shared secret using bilinear pairing.

        CORE SECURITY EQUATIONS (NON-INTERACTIVE KEY AGREEMENT):
        ─────────────────────────────────────────────────────
        EV side computes:
            K_EV = e(SK_EV, Q_EVSE)
                 = e((s_M_EV + s_M_EVSE) * Q_EV, Q_EVSE)

        EVSE side computes:
            K_EVSE = e(Q_EV, SK_EVSE)
                   = e(Q_EV, (s_M_EV + s_M_EVSE) * Q_EVSE)

        WHERE:
        - e: G1 × G1 → G2 (bilinear pairing / Weil pairing)
        - SK_EV: Cross-domain private key for EV
        - SK_EVSE: Cross-domain private key for EVSE
        - Q_EV, Q_EVSE: Identity public elements
        - s_M_EV, s_M_EVSE: Master secrets (scalar multipliers)

        BILINEARITY PROPERTY (Why both sides get same result):
        ──────────────────────────────────────────────────
        The bilinear pairing satisfies:
            e(a*P, b*Q) = e(P, b*a*Q) = e(b*P, a*Q) = e(P, Q)^(a*b)

        Therefore:
            e((s_M_EV + s_M_EVSE) * Q_EV, Q_EVSE)
                = e(Q_EV, Q_EVSE)^(s_M_EV + s_M_EVSE)
                = e(Q_EV, (s_M_EV + s_M_EVSE) * Q_EVSE)

        Both endpoints compute the SAME value despite computing different pairings.
        This is the magic that makes non-interactive agreement possible.

        NON-INTERACTIVE PROPERTY:
        ─────────────────────────
        1. No message exchange needed (both know each other's identity)
        2. No random nonces needed (identity is deterministic)
        3. No interactive protocol phases needed
        4. Shared secret computed entirely locally
        5. No cryptographic material appears on wire

        SECURITY ASSUMPTIONS:
        ────────────────────
        1. BDH (Bilinear Diffie-Hellman) assumption: given g, g^a, g^b, g^c,
           computing e(g, g)^(abc) is computationally hard
        2. Identities (MAC addresses) are globally unique
        3. Manufacturer master secrets remain secret
        4. Bilinear pairing is computable and verifiable

        Args:
            my_private_key: Combined private key (SK_NODE)
                           = (s_M_EV + s_M_EVSE) * Q_NODE
            peer_identity: Peer's identity string (MAC address)
            peer_manufacturer_tag: Peer's manufacturer tag ("M_EV" or "M_EVSE")

        Returns:
            Serialized shared secret (pairing element in G2, ~174 bytes for SS512)

        Cryptographer verification:
        ──────────────────────────
        Verify implementation matches:
        1. Bilinear pairing is implemented correctly (not just any e-function)
        2. Arguments to pairing are in correct groups (both G1 elements)
        3. Pairing output is in G2 (target group of bilinear map)
        4. Serialization preserves the full pairing element (no truncation)
        5. Serialization is deterministic (same input → same output)
        6. No hash of pairing result before serialization (raw element preserved)
        """
        # EQUATION: Q_PEER = H(ID_PEER || M_PEER)
        # Compute peer's identity public element deterministically
        # This is public data; both sides can compute it
        Q_peer = self.identity_public_key(peer_identity, peer_manufacturer_tag)

        # EQUATION (EV side):    K_EV = e(SK_EV, Q_EVSE)
        # EQUATION (EVSE side):  K_EVSE = e(Q_EV, SK_EVSE)
        # Compute bilinear pairing between:
        #   - My private key (scalar-multiplied identity element)
        #   - Peer's identity public element
        # Result is in G2 (target group of bilinear map)
        shared_element = pair(my_private_key.secret_key, Q_peer)

        # Serialize the pairing result to bytes
        # Output: ~174 bytes for SS512 pairing (complete group element)
        return self.group.serialize(shared_element)

    @staticmethod
    def derive_nmk(
        shared_secret: bytes,
        run_id: bytes,
        ev_identity: str,
        evse_identity: str,
    ) -> bytes:
        """Derive NMK from shared secret via SHA-256.

        KEY DERIVATION EQUATION (FROM PAIRING TO NMK):
        ──────────────────────────────────────────
        NMK = SHA256(shared || context)[:16]

        WHERE:
        - shared: Serialized pairing output e(Q_EV, Q_EVSE)^(s_M_EV + s_M_EVSE)
                 (~174 bytes for SS512)
        - context: Domain-separation string combining:
            * Protocol version ("SLAC-IBC-NMK-v1")
            * Run ID (from SLAC handshake, typically 8 zero bytes)
            * EV identity string (MAC address with M_EV tag)
            * EVSE identity string (MAC address with M_EVSE tag)
        - SHA256(...).digest()[:16]: Take first 16 bytes of SHA256 output
                                    = 128-bit AES-128 key

        DOMAIN SEPARATION PURPOSE:
        ──────────────────────────
        Inclusion of both identities in context ensures:
        1. Different identities → different NMKs (even with same run_id)
        2. Identity swap attacks prevented (ev_identity ≠ evse_identity)
        3. Cross-session independence (different run_ids → different NMKs)
        4. Protocol binding (NMK tied to this specific SLAC session)

        KEY DERIVATION FUNCTION (KDF) RATIONALE:
        ────────────────────────────────────────
        Uses SHA256 rather than raw pairing output because:
        1. Reduces output from 174 bytes to 16 bytes (AES-128 block)
        2. Compresses entropy from pairing onto AES key space
        3. Provides final level of security against partial pairing leaks
        4. Follows KDF best practices (hash not used for encryption directly)
        5. Deterministic: same inputs always produce same NMK

        IMPLEMENTATION NOTES:
        ────────────────────
        - No random component: NMK is deterministic from identities + run_id
        - No nonce needed: safety comes from bilinearity, not randomness
        - Reproducible: both sides compute identically without coordination
        - Verifiable: third party knowing pairing could verify NMK (not private)

        Args:
            shared_secret: Serialized pairing output from derive_shared_secret
                          (174 bytes for SS512 after serialization)
            run_id: 8-byte run ID from SLAC parameter exchange
                   (currently all zeros, could be randomized per session)
            ev_identity: EV's identity string for domain separation
                        (format: "88fca61c81c2M_EV")
            evse_identity: EVSE's identity string for domain separation
                          (format: "88fca61c81bbM_EVSE")

        Returns:
            16-byte NMK (AES-128 key)

        Cryptographer verification:
        ──────────────────────────
        Verify implementation:
        1. SHA256 is cryptographic hash (FIPS 180-4 compliant)
        2. Context uses proper domain separation (clear delimiters "SLAC-IBC-NMK-v1")
        3. Both identities included (not just one)
        4. Output length is exactly 16 bytes
        5. No output truncation beyond [:16]
        6. Serialized pairing is used, not just binary representation
        7. Run ID is included in hash (session-specific binding)
        """
        # Construct domain-separation context string
        # Format: "SLAC-IBC-NMK-v1" | run_id | ev_identity | evse_identity
        context = (
            b"SLAC-IBC-NMK-v1"  # Protocol version tag for this KDF
            + b"|"              # Delimiter
            + run_id            # 8-byte run ID from SLAC (session-specific)
            + b"|"              # Delimiter
            + ev_identity.encode("utf-8")    # EV MAC + "M_EV"
            + b"|"              # Delimiter
            + evse_identity.encode("utf-8")  # EVSE MAC + "M_EVSE"
        )

        # EQUATION: NMK = SHA256(shared || context)[:16]
        # Hash the concatenation of:
        #   - shared: serialized bilinear pairing output (174 bytes for SS512)
        #   - context: domain-separation string (~70 bytes)
        # Output: 256-bit SHA256 digest, truncate to first 128 bits (16 bytes)
        nmk_full = sha256(shared_secret + context).digest()
        nmk_128bit = nmk_full[:16]  # Take first 16 bytes = 128 bits

        return nmk_128bit


if __name__ == "__main__":
    """Test: Verify both EV and EVSE derive identical NMK."""
    print("=" * 70)
    print("Certificateless Two-Party Key Establishment Verification")
    print("=" * 70)

    ibe = CertificatelessKeyEstablishment()

    # Identities (MAC addresses)
    ev_mac = "88fca61c81c2"
    evse_mac = "88fca61c81bb"

    # Manufacturer tags (distinguish identity public elements)
    M_EV = "M_EV"
    M_EVSE = "M_EVSE"

    print("\n[1] Computing cross-domain private keys...")
    print(f"    EV identity:   {ev_mac} || {M_EV}")
    print(f"    EVSE identity: {evse_mac} || {M_EVSE}")

    # EV node computes its private key
    ev_sk = ibe.compute_cross_domain_private_key(ev_mac, M_EV)
    print(f"    ✓ EV private key computed (combined from both manufacturers)")

    # EVSE node computes its private key
    evse_sk = ibe.compute_cross_domain_private_key(evse_mac, M_EVSE)
    print(f"    ✓ EVSE private key computed (combined from both manufacturers)")

    print("\n[2] Deriving shared secrets via bilinear pairing...")
    # EV computes: K_EV = e(SK_EV, Q_EVSE)
    ev_shared = ibe.derive_shared_secret(ev_sk, evse_mac, M_EVSE)
    print(f"    ✓ EV computed: e(SK_EV, Q_EVSE)")

    # EVSE computes: K_EVSE = e(Q_EV, SK_EVSE)
    evse_shared = ibe.derive_shared_secret(evse_sk, ev_mac, M_EV)
    print(f"    ✓ EVSE computed: e(Q_EV, SK_EVSE)")

    print("\n[3] Deriving NMK from shared secrets...")
    run_id = bytes(8)  # Currently hardcoded zeros; could be randomized per session

    ev_nmk = ibe.derive_nmk(ev_shared, run_id, ev_mac, evse_mac)
    evse_nmk = ibe.derive_nmk(evse_shared, run_id, ev_mac, evse_mac)

    print(f"    EV NMK:   {ev_nmk.hex()}")
    print(f"    EVSE NMK: {evse_nmk.hex()}")

    print("\n[4] Verification...")
    match = ev_nmk == evse_nmk
    print(f"    NMK Match: {match}")
    if match:
        print("\n✅ SUCCESS: Both sides derived identical NMK via non-interactive scheme")
    else:
        print("\n❌ FAILURE: NMK mismatch — check master secrets and identities")

    print(f"\nMaster Secrets (persistent, shared between all nodes):")
    print(f"    s_M_EV   (EV mfg):   {ibe.master_secret_ev_path}")
    print(f"    s_M_EVSE (EVSE mfg): {ibe.master_secret_evse_path}")
    print(f"    P (generator):       {ibe.generator_path}")
    print("=" * 70)
