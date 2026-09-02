# CLAUDE.md — CCS Plug-and-Charge Relay Attack Reproduction & Cross-Layer Binding Defense

> **Read this entire file before writing any code.** This is a research artifact for a
> peer-reviewed security paper. Correctness of the cryptography and honesty of the
> evaluation matter more than speed of delivery.
>
> **Revision 2 changes** — (1) topology corrected: the physical PLC link now sits on
> `Attacker EV ↔ Real EVSE` (§4). (2) The defense requires updating **both** the victim
> EV and the real EVSE, not the EVSE alone (§7.8). (3) Scenario S4 split into S4a/S4b.

---

## 0. Scope, Ethics, and Hard Constraints

### 0.1 What this project is

We reproduce a **published, responsibly-disclosed** vulnerability — the ISO 15118
Plug-and-Charge relay attack from Löw, Vasu, Hutzelmann and Hof, *"Charge It to My
Neighbor: A Relay Attack on ISO 15118 Plug and Charge Payment"* (USENIX VehicleSec
2026) — and then demonstrate a defense built on our own prior work
(*"Demo: Certificateless and Non-Interactive Key Establishment for Secure CCS EV
Charging"*, VehicleSec 2026).

The attack was disclosed to CharIN and to charging station manufacturers prior to
publication. Reproduction here is for the purpose of **evaluating a countermeasure**.

### 0.2 Hard constraints — never violate these

1. **Synthetic PKI only.** Every certificate, contract certificate, private key and
   manufacturer master secret in this repo is generated locally by our own test PKI
   scripts. Never import, embed, or use a real V2G Root CA, a real MO/CPO sub-CA, a
   real contract certificate, or credentials extracted from any real charging station.
2. **Isolated lab network only.** All traffic stays on the bench: PLC between the two
   devolo boards, and loopback / veth pairs / a dedicated lab switch. No code here may
   connect to a real charging station, a real OCPP backend, a real e-mobility
   operator, or any production network.
3. **No real vehicles.** The "victim vehicle" is a software stack. Do not add any
   feature that talks to a physical production EV.
4. **Fail closed.** Any component that cannot verify its configuration is synthetic
   (see `common/lab_guard.py`, §9.6) must refuse to start.
5. **Attack code is clearly marked.** Every module implementing relay behaviour lives
   under `relay/` and carries the banner in §9.7.

If a task would require breaking one of these, stop and ask the user rather than
improvising.

---

## 1. Project Goal (three deliverables, in order)

| # | Deliverable | Success criterion |
|---|---|---|
| **A** | Reproduce the Löw et al. relay attack end-to-end | Attacker EV charges; victim EV's contract is billed; captured in a pcap |
| **B** | PyQt GUI that visualises the attack live | Four endpoint panes, message flow animation, relay highlighted |
| **C** | Our cross-layer binding defense, and proof it stops the relay | Relayed `AuthorizationReq` rejected at the real EVSE; legitimate session still succeeds |

**Every deliverable must be runnable two ways: GUI and headless CLI.** The GUI is a
*view* over the same engine the CLI drives. No business logic in Qt classes. This is
non-negotiable — see §6.

---

## 2. Available Hardware

| Item | Count | Detail |
|---|---|---|
| devolo dLAN Green PHY Eval Board II | 2 | Qualcomm QCA7000 HPGP modem + NXP LPC1758 MCU |
| Ubuntu host PC | 1+ | Boards attach over Ethernet |
| Copper cable | 1 | Emulates the charging cable (PLC channel) |

**We have two boards but the relay needs four ISO 15118 endpoints.** This is expected.
Löw et al. did the same split: their hardware test used a real charging station and an
EV simulator, with powerline modems for the other roles.

**Critical caveat:** the pairing operation (`e(·,·)` on SS512) runs on the Ubuntu host,
not on the LPC1758. Never write anything claiming on-target embedded feasibility.
Report host-side timings and mark on-target execution as future work.

---

## 3. Existing Codebase Inventory

Repo: `noninteractive-ibc-slac`, branch `ibc-slac-multi-pkg`. A fork of SwitchEV/EcoG
`pyslac`.

### 3.1 Files that matter

| Path | Role |
|---|---|
| `pyslac/ibe_key_establishment.py` | **Core crypto.** `CertificatelessKeyEstablishment`. Cross-domain enrollment + pairing. Our published contribution. |
| `pyslac/session.py` | SLAC state machine (EVSE side). `cm_ibe_key_establishment()` ~line 559 derives `K` and the NMK. `evse_set_key()` programs the NMK into the QCA7000. |
| `pyslac/session_ecdh.py` | ECDH baseline, for comparison measurements |
| `pyslac/session_without_nmk_hash.py` | Plaintext-NMK baseline (stock CCS) |
| `pyslac/examples/ev_slac_scapy.py` | EV-side SLAC driver (scapy) |
| `pyslac/examples/single_slac_session.py` | EVSE-side entry point |
| `pyslac/messages.py`, `layer_2_headers.py`, `enums.py` | HomePlug AV frame definitions |
| `wireshark_custom_plugins/homeplug_slac.lua` | Wireshark dissector for SLAC |
| `ibe_master_secret_ev.bin`, `ibe_master_secret_evse.bin` | Persisted master secrets (dev only) |

### 3.2 Known defects — fix these first

1. **Hardcoded absolute paths.** `CertificatelessKeyEstablishment.__init__` defaults to
   `/home/jack/projects/noninteractive-ibc-slac/...`. Resolve from env var
   `IBC_KEY_DIR` (default `./keys/`), created if missing.
2. **`run_id` is `bytes(8)` of zeros.** The NMK is therefore identical for every
   session between the same pair. Thread the real SLAC RunID through. This is a
   **security fix**, not cleanup — without it `K_bind` never varies and the `sid`
   argument in the KDF does nothing.
3. **Files named `* copy.py`, `zbackofexamples copy/`.** Move to `attic/`. Never import.
4. **`requirements.txt` self-references the GitHub repo** at a pinned commit. Remove;
   install from the local source tree.
5. **`Dockerfile` runs `poetry update` at build time** — non-reproducible. Pin with
   `poetry.lock`, use `poetry install --no-root`.

### 3.3 Crypto reference (as implemented, and as it must stay)

```
Q_EV    = H(ID_EV   || "M_EV")                    # hash-to-G1
Q_EVSE  = H(ID_EVSE || "M_EVSE")

SK_EV   = s_M_EV * Q_EV   + s_M_EVSE * Q_EV       # cross-domain enrollment
SK_EVSE = s_M_EV * Q_EVSE + s_M_EVSE * Q_EVSE

K_EV    = e(SK_EV, Q_EVSE)
K_EVSE  = e(Q_EV, SK_EVSE)
K       = e(Q_EV, Q_EVSE)^(s_M_EV + s_M_EVSE)     # both sides equal
```

`ID_EV` / `ID_EVSE` are board MAC addresses. Group is Charm-Crypto `SS512`.

> **Do not replace this with static Diffie-Hellman over published public keys**
> (`Z_i = z_i·P`, `S_ij = z_i·z_j·P`). That variant is broken: an adversary registers
> `Z_F = a·Z_R` and `Z_A = a·Z_V`, making `S_{V,F} = S_{A,R}` and defeating the binding
> using public values alone. The hash-to-group construction blocks this because the
> adversary cannot relate `Q_F` and `Q_R` by a known scalar. If DH-style key material
> ever appears in the binding path, treat it as a bug.

---

## 4. Testbed Topology ★ REVISED IN R2

Four ISO 15118 endpoints on two boards plus host processes.

```
┌──────────────────────── Ubuntu Host PC ─────────────────────────┐
│                                                                  │
│   ┌──────────────┐   virtual IPv6   ┌──────────────┐            │
│   │  VICTIM EV   │◄────────────────►│  FAKE EVSE   │◄─ ─ ─ ─ ─ ─│─ ─ ┐
│   │   (V)        │  K_{V,F} derived │   (F)        │            │    │
│   │   Docker     │     locally      │   Docker     │            │  key file
│   └──────────────┘                  └──────┬───────┘            │ (compromised
│                                            │                    │   station)
│                              TCP relay     │ + tc netem delay   │
│                                            │                    │
│   ┌──────────────┐                  ┌──────▼───────┐            │
│   │  REAL EVSE   │                  │ ATTACKER EV  │            │
│   │   (R)        │                  │   (A)        │            │
│   │   Host app   │                  │   Host app   │            │
│   └──────┬───────┘                  └──────┬───────┘            │
└──────────┼─────────────────────────────────┼────────────────────┘
           │ Ethernet                        │ Ethernet
    ┌──────▼───────┐                  ┌──────▼───────┐
    │ devolo board │◄── J3 PLC ──────►│ devolo board │
    │  EVSE mode   │  copper cable    │   PEV mode   │
    └──────────────┘  real SLAC →     └──────────────┘
                       K_{A,R}
```

See `docs/testbed-system-design.tex` for the publication figures.

### 4.1 Why the hardware goes on `A ↔ R`

**`R` is the party that rejects.** The defense's decisive moment is the real charging
station refusing the relayed `AuthorizationReq`. Putting that at the end of a real PLC
link, verified against a `K` derived over that link, is the strongest demonstration.
It also matches Löw et al.'s hardware configuration and reuses the existing working
two-board testbed without rewiring.

### 4.2 Why the virtual `V ↔ F` link is cryptographically equivalent

`K` is **non-interactive**. `V` and `F` each compute
`K_{V,F} = e(Q_V, Q_F)^(s_M_EV + s_M_EVSE)` locally from identities and issued private
keys, with nothing exchanged over the channel. A physical PLC link is not required to
produce it.

State this explicitly in the paper. It turns an equipment limitation into a
demonstration of the scheme's central property.

### 4.3 The fifth entity

The **compromised charging station** never participates in the protocol. It exists
only as the source of the credential `F` presents. Model it as
`pki/out/compromised_station/`, produced by the PKI script and loaded by `F` at
startup. Render it in diagrams as a detached, dotted key store.

### 4.4 Deployment matrix

| Endpoint | Runs as | Network | Board |
|---|---|---|---|
| Victim EV `V` | Docker `victim-ev` | veth pair, namespace `ns-v` | none |
| Fake EVSE `F` | Docker `fake-evse` | veth pair, namespace `ns-f` | none |
| Real EVSE `R` | Host process | host net, `CAP_NET_RAW`, `CAP_NET_ADMIN` | EVSE-mode board |
| Attacker EV `A` | Host process | host net, `CAP_NET_RAW`, `CAP_NET_ADMIN` | PEV-mode board |

`R` and `A` run natively because they drive the boards: scapy must write raw HomePlug
AV frames (EtherType `0x88E1`) to the board interfaces, which is simplest on the host.
`V` and `F` are containerised because their link is virtual.

### 4.5 Single-PC vs two-PC

- **1 PC (minimum, works)**: everything on one host; relay link is loopback TCP with
  `tc netem` delay.
- **2 PCs (preferred for the paper)**: PC1 hosts `V`+`F`; PC2 drives both boards and
  hosts `R`+`A`. The relay then crosses a real network, giving honest RTT numbers.

Support both via config. Never hardcode `localhost`.

---

## 5. Target Repository Layout

Monorepo alongside the existing `pyslac` package. **Do not fork `pyslac` again** —
import it.

```
ccs-relay-testbed/
├── CLAUDE.md                       # this file
├── README.md
├── pyproject.toml
├── Makefile                        # every workflow has a make target
│
├── pyslac/                         # EXISTING — patched, not rewritten
│   └── ibe_key_establishment.py    #   + K_bind derivation (§7.2)
│
├── common/
│   ├── config.py                   # dataclass config from YAML/env
│   ├── lab_guard.py                # §9.6 synthetic-material check
│   ├── events.py                   # EventBus + Event dataclasses (§6.2)
│   ├── logging_setup.py
│   ├── pairing.py                  # pairing backend abstraction (§9.1)
│   ├── pcap.py
│   └── binding.py                  # OUR DEFENSE: K_bind, ctx, tau (§7)
│
├── pki/
│   ├── generate_pki.py             # V2G root, CPO/MO sub-CAs, contract certs
│   ├── generate_ibc_material.py    # master secrets, per-identity SK, manifest
│   └── out/                        # .gitignored
│
├── iso15118/
│   ├── messages.py
│   ├── codec.py                    # EXI or JSON shim (§8.1)
│   ├── sdp.py
│   ├── tls.py                      # TLS wrapper + keylog export
│   ├── secc.py                     # station state machine
│   ├── evcc.py                     # vehicle state machine
│   └── pnc.py                      # challenge, sign, verify
│
├── endpoints/
│   ├── victim_ev.py
│   ├── fake_evse.py
│   ├── real_evse.py
│   ├── attacker_ev.py
│   └── legit_ev.py                 # positive control (§10.6)
│
├── relay/                          # ⚠ ATTACK CODE — §9.7 banner
│   ├── channel.py
│   └── orchestrator.py
│
├── engine/
│   ├── scenario.py
│   ├── runner.py
│   └── scenarios/
│       ├── s1_baseline_relay.yaml
│       ├── s2_ibc_slac_only.yaml
│       ├── s3_binding_defense.yaml
│       ├── s4a_cloned_evse_id_binding.yaml
│       ├── s4b_cloned_our_binding.yaml
│       └── s5_legitimate_control.yaml
│
├── cli/main.py
├── gui/                            # PyQt6 — VIEW ONLY
│   ├── main_window.py
│   ├── endpoint_pane.py
│   ├── sequence_view.py
│   ├── crypto_inspector.py
│   └── scenario_panel.py
│
├── docker/
│   ├── Dockerfile.base
│   ├── Dockerfile.victim-ev
│   ├── Dockerfile.fake-evse
│   ├── docker-compose.yml
│   └── entrypoint.sh
│
├── docs/
│   └── testbed-system-design.tex   # publication figures
│
├── results/                        # .gitignored
├── scripts/
│   ├── setup_veth.sh               # namespaces for V and F
│   ├── setup_boards.sh             # bring up board interfaces for R and A
│   ├── install_charm_host.sh       # Charm-Crypto on the host (R, A need it)
│   ├── setup_netem.sh
│   ├── capture.sh
│   └── teardown.sh
└── tests/
    ├── test_binding.py             # ★ most important — §10.7
    ├── test_ibc.py
    ├── test_pnc.py
    ├── test_relay.py
    └── test_scenarios.py
```

---

## 6. Architecture Rule: GUI and CLI Share One Engine

### 6.1 The rule

```
                    ┌──────────────┐
                    │  engine/     │   ← ALL logic lives here
                    │  runner.py   │
                    └──────┬───────┘
                           │ emits Events onto EventBus
                 ┌─────────┴─────────┐
                 ▼                   ▼
          ┌────────────┐      ┌────────────┐
          │  cli/      │      │  gui/      │
          │  prints    │      │  renders   │
          └────────────┘      └────────────┘
```

- `engine/` **must not import PyQt**. Ever.
- `gui/` contains **zero** protocol, crypto, or networking code.
- A scenario must produce byte-identical `results/*.json` from GUI or CLI. Enforced by
  `tests/test_scenarios.py::test_gui_cli_parity`.

### 6.2 Event model

```python
# common/events.py
from dataclasses import dataclass, field
from enum import Enum
import time

class EventKind(Enum):
    PHASE_START      = "phase_start"       # SLAC / SDP / TLS / PNC
    MESSAGE_SENT     = "message_sent"
    MESSAGE_RECV     = "message_recv"
    RELAY_FORWARD    = "relay_forward"     # ⚠ red in GUI
    CRYPTO_DERIVED   = "crypto_derived"    # K, K_bind, tau, NMK
    SIGNATURE_MADE   = "signature_made"
    VERIFY_OK        = "verify_ok"
    VERIFY_FAIL      = "verify_fail"       # ★ the money event in S3/S4b
    SESSION_ABORT    = "session_abort"
    CHARGING_STARTED = "charging_started"
    BILLED           = "billed"            # which contract got charged
    TIMING           = "timing"

@dataclass
class Event:
    kind: EventKind
    endpoint: str                # "V" | "F" | "A" | "R"
    ts: float = field(default_factory=time.monotonic)
    label: str = ""
    payload: dict = field(default_factory=dict)
    correlation_id: str | None = None   # ties relayed pairs together
```

`correlation_id` lets the GUI draw the arrow proving the challenge `R → A` is the
*same bytes* as `F → V`. Set it on every relayed item.

### 6.3 EventBus

`asyncio.Queue`-backed, multi-subscriber, non-blocking. If the GUI is slow, drop
animation frames but **never** drop events destined for the JSON log.

---

## 7. Our Defense — Exact Specification

### 7.1 Where it plugs in

Two touchpoints only.

| Phase | Layer | Change |
|---|---|---|
| **1 — SLAC** | ISO 15118-3 | Already derive `K`. **Add**: also derive `K_bind`. |
| 2 — SDP/TCP/TLS | — | **No change.** `K_bind` carried in memory. |
| **3 — Plug & Charge** | ISO 15118-2/-20 | **Add**: compute `τ` locally; sign `h(C_R ‖ τ)` instead of `C_R` |

### 7.2 Key derivation (`common/binding.py`)

```
ctx = ID_EV || ID_EVSE || RunID || SessionID

K_NMK  = HKDF(K, "SLAC-NMK" || ctx)      # phase 1, existing
K_bind = HKDF(K, "PnC-BIND" || ctx)      # phase 1, NEW
```

Use `cryptography.hazmat.primitives.kdf.hkdf.HKDF`, SHA-256, label and ctx in `info=`,
32-byte output.

**Phase-ordering note**: `SessionID` comes from `SessionSetupReq/Res`, *after* SDP and
TLS. So `K_bind` cannot be finalised at SLAC time if `ctx` includes it. Default to (a):

- **(a) Two-stage**: at SLAC compute
  `K_bind_pre = HKDF(K, "PnC-BIND" || ID_EV || ID_EVSE || RunID)`; at SessionSetup
  finalise `K_bind = HKDF(K_bind_pre, "PnC-BIND-SESSION" || SessionID)`.
- (b) Drop `SessionID`, rely on `RunID` alone. Weaker session binding.

### 7.3 Binding token and signature

```
tau = HMAC_SHA256(
    K_bind,
    C_R || ID_EV || ID_EVSE || RunID || SessionID || SHA256(Cert_contract_DER)
)

sigma = Sign(sk_contract, SHA256(C_R || tau))
```

**Context fields appear both inside `K_bind` and explicitly inside `tau`. This
redundancy is deliberate** — session binding survives even if the KDF context is
misimplemented. Put exactly this comment in the code; it is also a sentence in the
paper.

### 7.4 THE critical invariant

> **`τ` is derived locally by each endpoint and is NEVER transmitted.**

Enforce in code and tests:

- `tau` must not appear in any message dataclass field.
- `tests/test_binding.py::test_tau_never_on_wire` scans every serialised frame in a
  captured session and asserts the `tau` bytes do not appear.
- Comment block above the computation stating this is a security requirement, not an
  implementation detail: if a peer could supply `τ`, the attacker would hand over the
  other session's value and the vulnerability returns.

### 7.5 Verification at the EVSE

```python
expected_tau = compute_tau(local_K_bind, C_R, ...)   # from ITS OWN session
ok = verify(pk_contract, sigma, sha256(C_R + expected_tau))
```

The station uses the identity of the vehicle **physically on its cable**, not any
identity asserted in the relayed message. Make this explicit in the code path.

### 7.6 Fix the RunID freshness bug

`derive_nmk` currently receives `bytes(8)` of zeros. Thread the real SLAC RunID
through from `session.py`. Without this, `K_bind` is identical every session.

### 7.7 Feature flags

Every scenario is the same code path with flags:

```yaml
slac_mode:          plaintext_nmk | ecdh | ibc
pnc_mode:           baseline | evse_id_binding | our_binding
relay:              enabled | disabled
fake_evse_identity: synthetic | cloned_from_real
```

`evse_id_binding` implements Löw et al. §7.3 so we can show the cloned-station case
where it fails and ours holds.

### 7.8 ★ Both endpoints must be updated (NEW IN R2)

The defense changes **both** the vehicle and the station:

| Endpoint | Baseline (S1/S2) | Defense (S3/S4b/S5) |
|---|---|---|
| Victim EV `V` | unmodified — signs `C_R` | **updated** — computes `τ`, signs `h(C_R ‖ τ)` |
| Real EVSE `R` | unmodified — verifies against `C_R` | **updated** — recomputes `τ`, verifies against `h(C_R ‖ τ)` |

An unmodified vehicle signs the bare challenge and there is nothing to bind. **Do not
build the victim as permanently unmodified** — give it a `pnc_mode` flag like every
other endpoint.

This is also the deployment story for the paper: updated vehicles are protected
regardless of the station, but the vehicle is the party that must change.

---

## 8. Deliverable A — Reproducing the Relay Attack

### 8.1 Ground truth and the ISO 15118 stack

Löw et al.'s PoC repo (`securityinmobility/plug-and-charge-relay-poc`) is assumed
unavailable. Build from the EcoG/SwitchEV stack (`github.com/EcoG-io/iso15118`) or
implement the minimal subset ourselves.

**Recommendation: implement the minimal subset.** We need only:

```
SupportedAppProtocolReq/Res
SessionSetupReq/Res
ServiceDiscoveryReq/Res
PaymentServiceSelectionReq/Res
PaymentDetailsReq/Res           ← ContractCertificate in; 16-byte challenge out
AuthorizationReq/Res            ← carries the signature
ChargeParameterDiscoveryReq/Res (stub — enough to show "charging continues")
```

Full EXI is a heavy dependency. Use a pluggable codec (`iso15118/codec.py`) with a
JSON-over-TLS shim by default and an optional EXI backend. Document in the paper that
the codec is a shim and that the vulnerability is codec-independent.

### 8.2 The relay itself

Only three items are relayed. Nothing else.

| Item | Direction |
|---|---|
| `ContractCertificate` | V → F → A → R |
| 16-byte challenge `C_R` | R → A → F → V |
| Signature `σ` | V → F → A → R |

`A` stalls after `PaymentServiceSelectionRes` waiting for the certificate from `F`.
This stall is visible in the pcap and reproduces Löw et al.'s Figure 3.

### 8.3 Timing

ISO 15118 allows 2 s for `PaymentDetailsReq` and `AuthorizationReq`. Add configurable
delay on the relay link (`scripts/setup_netem.sh`, default 50 ms each way) and record
actual end-to-end latency. Show the margin.

### 8.4 Success criteria

- [ ] `A` completes authorization at `R` using `V`'s contract
- [ ] `R`'s billing record names `V`'s contract ID
- [ ] `V`'s session aborts after handing over the signature
- [ ] pcap captured and dissectable, showing both sessions interleaved
- [ ] `results/s1/*.json` records `BILLED{contract: V}` and `CHARGING_STARTED{endpoint: A}`

---

## 9. Implementation Notes and Gotchas

### 9.1 Charm-Crypto installation

Hardest dependency. Needs PBC and GMP from source. Pin in `Dockerfile.base`:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential m4 libgmp-dev libssl-dev flex bison wget && \
    wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
    tar -xzf pbc-0.5.14.tar.gz && cd pbc-0.5.14 && \
    ./configure && make && make install && ldconfig
```

Then install `charm-crypto` against that PBC. Cache the layer — it is slow. Put the
pairing behind `common/pairing.py` so another backend can be swapped in; the scheme is
backend-agnostic.

**`R` and `A` run natively**, so Charm must be installed on the host too, not only in
containers. Provide `scripts/install_charm_host.sh` and verify both paths produce
identical `K` for the same identities (`tests/test_ibc.py::test_host_container_parity`).

### 9.2 Raw frames and board access

`R` and `A` write EtherType `0x88E1` to the board interfaces. Run them with
`CAP_NET_RAW` + `CAP_NET_ADMIN`. `scripts/setup_boards.sh` brings up both interfaces
and prints their MACs — **those MACs are the IBC identities** `ID_EVSE` and `ID_EV` for
the `A ↔ R` pair, and must be written into the scenario config, not hardcoded.

### 9.3 Virtual link for `V ↔ F`

Two network namespaces joined by a veth pair (`scripts/setup_veth.sh`) so link-local
IPv6 and SDP multicast to `ff02::1` are isolated from the host. Containers join these
namespaces. Do not use the default Docker bridge — multicast there is unreliable.

Since there is no PLC between `V` and `F`, their SLAC phase is **simulated**: both
endpoints compute `K_{V,F}` directly from identities via
`CertificatelessKeyEstablishment`. Log a `CRYPTO_DERIVED` event with
`simulated_slac: true` so this is visible in the results and cannot be misreported in
the paper.

### 9.4 TLS keylog

Export `SSLKEYLOGFILE` from every endpoint to `results/<scenario>/keys.log` so
Wireshark can decrypt. Mirrors Löw et al. and is needed for the figures.

### 9.5 Capture

`dsV2Gshark` dissects V2G; our `homeplug_slac.lua` dissects SLAC. `scripts/capture.sh`
starts `dumpcap` on both board interfaces and the veth pair, one pcap per scenario.

### 9.6 `common/lab_guard.py`

```python
def assert_lab_only(config) -> None:
    """Refuse to run against non-synthetic material. Called by EVERY endpoint
    at startup, before any socket is opened."""
    # - every cert chain must terminate at pki/out/v2g_root_TEST.pem
    # - every cert subject must contain "LAB-TEST"
    # - no configured peer address outside RFC1918 / link-local / loopback
    # - refuse if IBC_KEY_DIR contains files absent from the generated manifest
    #   (manifest holds SHA-256 digests written by generate_ibc_material.py)
    # Raise LabGuardError and exit(2) on any violation.
```

### 9.7 Banner for attack code

Every file under `relay/`, plus `endpoints/fake_evse.py` and
`endpoints/attacker_ev.py`:

```python
# ─────────────────────────────────────────────────────────────────────────────
# ⚠ ATTACK CODE — RESEARCH USE ONLY
# Reproduces the ISO 15118 Plug-and-Charge relay attack (Löw et al., USENIX
# VehicleSec 2026) for the purpose of evaluating a countermeasure.
# Operates ONLY against the synthetic lab PKI in pki/out/ and ONLY on the
# isolated bench network. See CLAUDE.md §0.
# ─────────────────────────────────────────────────────────────────────────────
```

### 9.8 Determinism

Every scenario takes `--seed`. In `--mode replay` all nonces, challenges and session
IDs derive from it, so runs are reproducible for the paper. Real randomness in
`--mode live`.

---

## 10. Evaluation Matrix

Six runs, mapping 1:1 onto the paper's evaluation section.

| Scenario | SLAC | PnC mode | Victim EV | Real EVSE | Expected outcome |
|---|---|---|---|---|---|
| S1 baseline | plaintext NMK | baseline | unmodified | unmodified | relay **succeeds** |
| S2 IBC-SLAC only | IBC | baseline | unmodified | unmodified | relay **still succeeds** |
| S3 IBC + binding | IBC | our_binding | updated | updated | relay **rejected** |
| S4a cloned station | IBC | evse_id_binding | updated | updated | relay **succeeds** |
| S4b cloned station | IBC | our_binding | updated | updated | relay **rejected** |
| S5 control | IBC | our_binding | updated | updated | charging **authorized** |

### 10.1 S1 — Baseline relay

Reproduces Löw et al. Deliverable A is complete when this passes.

### 10.2 S2 — IBC-SLAC only (★ the negative result)

**Expect the relay to still succeed. This is deliberate. Do not "fix" it.**

It proves that securing key establishment alone does not stop an application-layer
relay, because the fake station is a legitimate endpoint rather than an eavesdropper.
It is one of the most valuable results in the paper.

GUI must show a banner: *"NMK secured — relay still succeeds. Link-layer
confidentiality is not relay resistance."*

Any agent tempted to make this test "pass" should re-read this section.

### 10.3 S3 — IBC-SLAC + our binding

`K_bind^{V,F} ≠ K_bind^{A,R}` ⟹ `τ_{V,F} ≠ τ_{A,R}` ⟹ `VERIFY_FAIL` at `R`.

### 10.4 S4a / S4b — Cloned station identity (★ our advantage)

Provision `F` with `R`'s identity **and** its IBC private key, so `Q_F = Q_R`.

- **S4a** (`evse_id_binding`): Löw et al.'s §7.3 mitigation. Both sides see `ID_R`, the
  binding matches, and **the relay succeeds**. Their mitigation fails here.
- **S4b** (`our_binding`): still fails for the attacker, because `Q_V ≠ Q_A` so the
  pairings differ.

The side-by-side is the strongest figure in the paper. Produce both from one command:
`ccs-testbed run --scenario s4a,s4b --compare`.

### 10.5 S5 — Legitimate control

`relay: disabled`, `V ↔ R` directly, binding on. **Authorization must succeed.**

Without this a reviewer cannot tell whether we built a defense or just broke
authorization. Never present S3/S4b without S5.

### 10.6 S5 wiring note

S5 needs `V` talking to `R`. Since `R` drives a board and `V` is containerised, either:

- run `V` as a host process for S5 (**preferred** — `legit_ev.py` against the PEV
  board, giving one fully-hardware legitimate session for the paper), or
- run S5 fully virtual with both endpoints simulated, and label it as such in results.

### 10.7 Unit-test obligations

`tests/test_binding.py` must contain at minimum:

```python
def test_same_pair_same_tau()                 # V,R both derive identical tau
def test_different_pairs_differ()             # tau_{V,F} != tau_{A,R}
def test_cloned_evse_still_differs()          # Q_F == Q_R but tau still differs
def test_tau_never_on_wire()                  # scan all frames for tau bytes
def test_attacker_cannot_resign()             # holding both K_bind values is insufficient
def test_runid_freshness()                    # different RunID -> different K_bind
def test_domain_separation()                  # K_NMK independent of K_bind
def test_unmodified_victim_has_no_binding()   # baseline mode signs C_R alone
```

---

## 11. Performance Measurements

Write to `results/timings.csv`. These become the paper's overhead table.

| Metric | How |
|---|---|
| Pairing computation (first contact) | `perf_counter_ns()` around `derive_shared_secret` |
| Cached per-session KDF cost | around `HKDF` calls |
| HMAC cost for `τ` | around `compute_tau` |
| Signature generation / verification | around sign/verify |
| Added bytes on the wire | **must be 0** — assert it |
| Added messages | **must be 0** — assert it |
| End-to-end `AuthorizationReq` latency | with and without binding |
| SLAC completion time | ibc vs ecdh vs plaintext baseline |
| Relay link RTT | measured, with the netem setting recorded |

Run each ≥30 times; report median and IQR, not mean alone.

**SLAC timings must come from the real PLC link (`A ↔ R`), never from the simulated
`V ↔ F` link.** Tag every timing row with `link: physical | simulated`. Reporting a
simulated SLAC time as hardware measurement would be a serious integrity error.

---

## 12. GUI Specification (PyQt6)

### 12.1 Layout

```
┌───────────────────────────────────────────────────────────────────────┐
│  Scenario: [S3 ▾]  Mode: [IBC+Binding ▾]  [▶ Run] [⏸] [⏹] [Export]   │
├──────────────┬──────────────┬──────────────┬──────────────────────────┤
│  VICTIM EV   │  FAKE EVSE   │ ATTACKER EV  │      REAL EVSE           │
│  virtual     │  virtual     │  board: PEV  │      board: EVSE         │
│  ● running   │  ● running   │  ● stalled   │      ● running           │
├──────────────┴──────────────┴──────────────┴──────────────────────────┤
│                     SEQUENCE DIAGRAM (animated)                        │
│   V ──PaymentDetailsReq──► F ┈┈relay┈┈► A ──PaymentDetailsReq──► R    │
├───────────────────────────────┬────────────────────────────────────────┤
│  CRYPTO INSPECTOR             │  EVENT LOG (filterable)                │
│  K^{V,F}     : a3f2…          │  12:04:31 [V] SIGNATURE_MADE           │
│  K_bind^{V,F}: 91bc…          │  12:04:31 [A] RELAY_FORWARD  σ         │
│  τ_{V,F}     : 4d0e…          │  12:04:31 [R] VERIFY_FAIL ✗            │
│  τ_{A,R}     : 77a1…  ✗ MISMATCH│                                      │
└───────────────────────────────┴────────────────────────────────────────┘
```

### 12.2 Requirements

- Relayed messages in **red**, dashed connector between the two sessions.
- Crypto inspector shows `τ` from both sessions side by side with an explicit
  MATCH / MISMATCH badge. **This is the single most important visual in the demo.**
- Endpoint panes label whether that endpoint is on **real hardware** or **virtual**, so
  the hybrid testbed is never misread by an audience.
- **Step mode**: pause at each protocol message with a "next" button, for narration.
- Export writes pcap + JSON + a PNG of the sequence diagram to `results/<scenario>/`.
- Endpoint states: `idle / slac / sdp / tls / pnc / charging / aborted`.
- Driven entirely from `EventBus`. No polling of protocol internals.

### 12.3 CLI parity

```bash
ccs-testbed run --scenario s3_binding_defense --seed 42 --out results/
ccs-testbed run --config my_run.yaml
ccs-testbed run --scenario s1 --no-gui --json-only
ccs-testbed run --scenario s4a,s4b --compare
ccs-testbed compare --scenarios s1,s2,s3,s4a,s4b,s5 --table   # LaTeX out
ccs-testbed bench --repeat 30 --out results/timings.csv
```

`compare --table` emits a LaTeX `tabular` ready to paste into the paper.

---

## 13. Build Order

**Do not skip ahead. Each step needs passing tests before the next.**

1. Repo skeleton, `pyproject.toml`, `Makefile`, CI stub.
2. Fix the five defects in §3.2. Existing tests still pass.
3. `common/`: config, events, EventBus, logging, pairing backend, lab_guard.
4. `pki/generate_pki.py` and `pki/generate_ibc_material.py` (with manifest).
5. `scripts/setup_boards.sh`, `scripts/setup_veth.sh`, `scripts/install_charm_host.sh`.
   **Regression gate**: a plain IBC-SLAC session must still complete on the two boards
   after the refactor, matching the existing `CM_SLAC_MATCH.CNF` result.
6. `iso15118/` minimal stack, JSON codec, TLS wrapper. Test `V ↔ R` happy path.
7. `endpoints/` four roles, CLI only. Each runs standalone.
8. `relay/` + S1. **Deliverable A complete** — capture the pcap.
9. `engine/` scenario runner + S1/S2. Verify S2 shows the relay still succeeding.
10. `common/binding.py` + S3. **Our defense works.**
11. `evse_id_binding` mode + S4a/S4b. Our advantage demonstrated.
12. S5 positive control (host-process victim against the PEV board).
13. `gui/` — last. The engine is stable by now and the GUI is a pure view.
14. `bench` + `compare` — measurement and LaTeX export.
15. Docker packaging + reproducibility check on a clean machine.

---

## 14. Coding Standards

- Python 3.10+. Type hints everywhere. `mypy` clean.
- `black` (88), `isort` (black profile), `flake8` per `.flake8`.
- `async`/`await` for all I/O. Run pairing operations in `asyncio.to_thread` — never
  block the event loop.
- Docstrings on crypto functions must state the **equation** implemented, matching
  §3.3 and §7. The existing `ibe_key_establishment.py` does this well — match it.
- No `print()` outside `cli/` and demo banners. Use the logger.
- Secrets never logged at INFO. `K`, `K_bind`, `SK` at DEBUG only, truncated to 8 hex
  chars, and only with `--reveal-secrets`. The GUI inspector is exempt (it is the point
  of the demo) but truncates by default.
- Commits: `feat(binding): …`, `fix(slac): …`, `test(relay): …`.

---

## 15. Definition of Done

- [ ] `make setup && make test` passes on a clean Ubuntu 22.04 machine
- [ ] Plain IBC-SLAC still runs on both boards after refactor (§13 step 5)
- [ ] Host and container both derive identical `K` for the same identities
- [ ] All six runs execute headless, producing JSON + pcap
- [ ] All six run in the GUI with identical JSON output
- [ ] `tests/test_binding.py` fully passing, including `test_tau_never_on_wire`
- [ ] S2 documented as an intentional negative result, not a bug
- [ ] S4a and S4b produce contrasting outcomes from one command
- [ ] S5 shows legitimate charging still authorizes
- [ ] `results/timings.csv` has ≥30 runs per configuration, tagged
      `link: physical | simulated`
- [ ] `ccs-testbed compare --table` emits valid LaTeX
- [ ] `lab_guard` blocks a deliberately-planted non-synthetic config (test this)
- [ ] README documents the hybrid topology, why `V ↔ F` is virtual and why that is
      cryptographically sound (§4.2), the host-side pairing caveat, and the exact
      commands to reproduce every figure

---

## 16. Open Questions — ask the user, do not guess

1. Real EXI, or is the JSON shim acceptable for the paper's claims?
2. One PC or two? Determines whether the relay link crosses a real network.
3. Pairing on the LPC1758, or host-side with a documented caveat?
4. `SessionID` two-stage `K_bind` (§7.2a) or RunID-only (§7.2b)?
5. Target venue and deadline — sets how much of §11's rigour is needed.
