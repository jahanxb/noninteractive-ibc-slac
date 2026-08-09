# Certificateless Two-Party Key Establishment Implementation

## Overview
Successfully implemented the certificateless non-interactive Identity-Based Cryptography (IBC) scheme as specified in:
**"Demo: Certificateless and Non-Interactive Key Establishment for Secure CCS EV Charging"**

## Key Changes

### 1. Core Cryptographic Module (`pyslac/ibe_key_establishment.py`)
**Complete rewrite** following the LaTeX equations exactly.

#### Old Scheme (Boneh-Franklin IBE)
- Single master secret `s`
- Private key: `SK_ID = s * H(ID)`
- Shared secret: `e(SK_EV, H(ID_EVSE))`

#### New Scheme (Certificateless Two-Party IBC)
- **Two independent manufacturers** with separate master secrets:
  - EV manufacturer: `s_M_EV`, public key `mpk_M_EV = s_M_EV * P`
  - EVSE manufacturer: `s_M_EVSE`, public key `mpk_M_EVSE = s_M_EVSE * P`

- **Identity public elements** (per manufacturer):
  ```
  Q_EV = H(ID_EV || M_EV)
  Q_EVSE = H(ID_EVSE || M_EVSE)
  ```

- **Cross-domain enrollment** (combined private keys):
  ```
  SK_EV = s_M_EV * Q_EV + s_M_EVSE * Q_EV
       = (s_M_EV + s_M_EVSE) * Q_EV
  
  SK_EVSE = s_M_EV * Q_EVSE + s_M_EVSE * Q_EVSE
         = (s_M_EV + s_M_EVSE) * Q_EVSE
  ```

- **Shared secret derivation** (bilinear pairing):
  ```
  K_EV = e(SK_EV, Q_EVSE)
  K_EVSE = e(Q_EV, SK_EVSE)
  
  Both equal: e(Q_EV, Q_EVSE)^(s_M_EV + s_M_EVSE)
  ```

- **NMK derivation** (SHA-256 hash):
  ```
  NMK = SHA256(shared || context)[:16]
  context = "SLAC-IBC-NMK-v1" || run_id || identities
  ```

### 2. Key Cryptographic Functions

#### `CertificatelessKeyEstablishment.__init__()`
- Loads/generates TWO master secrets: `s_m_ev` and `s_m_evse`
- Files (persisted):
  - `ibe_master_secret_ev.bin` (EV manufacturer)
  - `ibe_master_secret_evse.bin` (EVSE manufacturer)
  - `ibe_generator.bin` (shared generator P)

#### `compute_cross_domain_private_key(identity, manufacturer_tag)`
- Computes `Q_ID = H(ID || M_TAG)`
- Computes partial keys from both manufacturers:
  - `s_M_EV * Q_ID`
  - `s_M_EVSE * Q_ID`
- Combines locally: `SK = partial_1 + partial_2`
- Returns `CertificatelessPrivateKey` object

#### `derive_shared_secret(my_private_key, peer_identity, peer_manufacturer_tag)`
- Computes peer's identity public element: `Q_PEER = H(PEER_ID || M_PEER)`
- Computes pairing: `e(SK_MY, Q_PEER)`
- Returns serialized pairing output (174 bytes for SS512)

#### `derive_nmk(shared_secret, run_id, ev_identity, evse_identity)`
- Derives NMK via SHA-256 with domain separation
- Input: shared secret (174 bytes) + context
- Output: 16-byte NMK

### 3. EVSE Side Integration (`pyslac/session.py`)
- Import changed: `IBEKeyEstablishment` → `CertificatelessKeyEstablishment`
- Updated `cm_ibe_key_establishment()` method:
  - Calls `compute_cross_domain_private_key(evse_mac, M_EVSE)`
  - Calls `derive_shared_secret(evse_sk, ev_mac, M_EV)`
  - Updated console output to reflect two-manufacturer scheme
  - Output labels changed to "CERTIFICATELESS KEY ESTABLISHMENT"

### 4. PEV Side Integration (`pyslac/examples/ev_slac_scapy.py`)
- Import changed: `IBEKeyEstablishment` → `CertificatelessKeyEstablishment`
- Updated `ibeKeyEstablishment()` function:
  - Calls `compute_cross_domain_private_key(ev_mac, M_EV)`
  - Calls `derive_shared_secret(ev_sk, evse_mac, M_EVSE)`
  - Updated console output to reflect cross-domain enrollment
  - Output labels changed to "CERTIFICATELESS KEY ESTABLISHMENT"

## Verification Results

### Test Run Output
```
EV NMK:   747dbf39693d1d9ec8adf5b1f0aedc03  (16 bytes)
EVSE NMK: 747dbf39693d1d9ec8adf5b1f0aedc03  (16 bytes)
Match:    True ✓
```

### Demo Completion
- **PEV**: "PEV-EVSE MATCHED Successfully!"
- **EVSE**: "PEV-EVSE MATCHED Successfully, Link Established"
- Both sides independently derived identical NMK
- **Zero additional protocol frames** (non-interactive)
- **Zero key material on wire**

## Master Secret Files

Three persistent cryptographic files are generated once and reused:

| File | Purpose | Owner | Size |
|------|---------|-------|------|
| `ibe_master_secret_ev.bin` | EV manufacturer's master secret `s_M_EV` | EV PKG | ~30 bytes |
| `ibe_master_secret_evse.bin` | EVSE manufacturer's master secret `s_M_EVSE` | EVSE PKG | ~30 bytes |
| `ibe_generator.bin` | Shared generator P (G1 element) | Both | ~90 bytes |

All three files must exist and be identical on all nodes. They are loaded at startup.

## Testbed Configuration

### Identity Strings
- **EV identity**: MAC without colons + "M_EV" suffix
  - Example: `88fca61c81c2M_EV`
- **EVSE identity**: MAC without colons + "M_EVSE" suffix
  - Example: `88fca61c81bbM_EVSE`

### Manufacturer Tags
- `M_EV`: EV manufacturer identifier
- `M_EVSE`: EVSE manufacturer identifier

### Pairing Group
- **Group name**: SS512 (Symmetric Type-A pairing group over 512-bit prime field)
- **Generator P**: Shared between both manufacturers
- **Hash function**: H: {0,1}* → G1 (via charm.toolbox.pairinggroup)

## Security Properties

1. **No Key Material on Wire**: All key material is computed locally; nothing is transmitted
2. **Non-Interactive**: No additional key-exchange frames beyond standard SLAC
3. **Certificateless**: No PKI overhead; identities derived from MAC addresses
4. **Cross-Domain**: Each node requires both manufacturers' master secrets to operate
5. **Bilinear Pairing**: Security based on Bilinear Diffie-Hellman (BDH) assumption
6. **Domain Separation**: Identity public elements include manufacturer tag to prevent attacks

## Implementation Correctness

### Bilinearity Verification
The pairing implementation correctly satisfies:
```
e(a*P, b*Q) = e(P, b*a*Q) = e(b*P, a*Q) = e(P, Q)^(a*b)
```

Both sides compute:
- EV: `e((s_M_EV + s_M_EVSE) * Q_EV, Q_EVSE)`
- EVSE: `e(Q_EV, (s_M_EV + s_M_EVSE) * Q_EVSE)`

By bilinearity, both equal `e(Q_EV, Q_EVSE)^(s_M_EV + s_M_EVSE)`.

### Test Coverage
- ✓ Identical NMK derivation on both sides
- ✓ Deterministic key derivation (same inputs → same output)
- ✓ Cross-domain key formula verified
- ✓ Bilinear pairing properties validated
- ✓ NMK domain separation (context includes identities)

## Files Modified

1. `pyslac/ibe_key_establishment.py` — Complete rewrite (new class, new methods)
2. `pyslac/session.py` — Updated EVSE side integration
3. `pyslac/examples/ev_slac_scapy.py` — Updated PEV side integration

## Backward Compatibility

**Breaking changes**: This implementation is not backward compatible with the previous Boneh-Franklin scheme. The class name, API, and cryptographic assumptions have changed fundamentally.

To revert to the old scheme, restore from:
- Git commit history (previous `ibe_key_establishment.py`)
- Backup of the old module (if created before rewrite)

## Running the Demo

### First Time
```bash
# Generate master secrets and generator (one-time)
cd /home/jack/projects/noninteractive-ibc-slac
venv/bin/python pyslac/ibe_key_establishment.py
# Output: "✅ SUCCESS: Both sides derived identical NMK via non-interactive scheme"
```

### Each Demo Run
```bash
# Terminal 1: EVSE side
sudo venv/bin/python -u pyslac/examples/single_slac_session.py

# Terminal 2: PEV side (within 30 seconds)
sudo venv/bin/python -u pyslac/examples/ev_slac_scapy.py
```

Both sides will print "CERTIFICATELESS KEY ESTABLISHMENT" steps and derive matching NMKs.

## References

LaTeX source: `"Demo: Certificateless and Non-Interactive Key Establishment for Secure CCS EV Charging"`

Mathematical notation follows the paper exactly:
- Initialization section (master secrets, generators, public keys)
- Cross-domain enrollment section (partial keys, combination)
- Shared-key derivation section (bilinear pairing formulas)

---

**Implementation Date**: 2025-07-27
**Status**: ✅ Complete and Verified
