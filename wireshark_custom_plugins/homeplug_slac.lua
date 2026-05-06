-- ============================================================
-- HomePlug AV SLAC Protocol Dissector
-- VehicleSecProject —  University of Alabama
--
-- Covers:
--   1. Standard SLAC (ISO 15118-3 / HomePlug Green PHY)
--   2. Dylan's ECDH Key Exchange (custom extension)
--   3. IBE Pairing-Based Key Establishment (research extension)
--
-- Install:
--   sudo cp homeplug_slac.lua /usr/lib/x86_64-linux-gnu/wireshark/plugins/
--   Then in Wireshark: Ctrl+Shift+L to reload
-- ============================================================

local slac_proto = Proto("hpav_slac", "HomePlug AV SLAC")

-- ── Protocol Fields ─────────────────────────────────────────

-- General
local f_mmtype       = ProtoField.uint16("hpav_slac.mmtype",       "MM Type",            base.HEX)
local f_mmtype_name  = ProtoField.string("hpav_slac.mmtype_name",  "Message Name")
local f_mmv          = ProtoField.uint8 ("hpav_slac.mmv",          "MM Version",         base.HEX)
local f_src_mac      = ProtoField.string("hpav_slac.src_mac",      "Source MAC")
local f_dst_mac      = ProtoField.string("hpav_slac.dst_mac",      "Destination MAC")
local f_direction    = ProtoField.string("hpav_slac.direction",    "Direction")
local f_session_note = ProtoField.string("hpav_slac.session_note", "Session Note")

-- CM_SET_KEY fields
local f_setkey_nmk   = ProtoField.string("hpav_slac.setkey_nmk",  "NMK Action")
local f_setkey_note  = ProtoField.string("hpav_slac.setkey_note", "Purpose")

-- CM_SLAC_PARM fields
local f_run_id       = ProtoField.bytes ("hpav_slac.run_id",       "Run ID (Session ID)")
local f_app_type     = ProtoField.string("hpav_slac.app_type",     "Application Type")
local f_sec_type     = ProtoField.string("hpav_slac.sec_type",     "Security Type")

-- CM_START_ATTEN_CHAR fields
local f_num_sounds   = ProtoField.string("hpav_slac.num_sounds",   "Number of Sounds")
local f_timeout      = ProtoField.string("hpav_slac.timeout",      "Timeout (ms)")
local f_resp_type    = ProtoField.string("hpav_slac.resp_type",    "Response Type")

-- CM_ATTEN_CHAR fields
local f_atten_avg    = ProtoField.string("hpav_slac.atten_avg",    "Avg Attenuation (dB)")
local f_num_groups   = ProtoField.string("hpav_slac.num_groups",   "Number of Groups")
local f_atten_note   = ProtoField.string("hpav_slac.atten_note",   "Measurement Note")

-- CM_SLAC_MATCH fields
local f_pev_mac      = ProtoField.string("hpav_slac.pev_mac",      "PEV MAC Address")
local f_evse_mac     = ProtoField.string("hpav_slac.evse_mac",     "EVSE MAC Address")
local f_match_result = ProtoField.string("hpav_slac.match_result", "Match Result")
local f_nmk_note     = ProtoField.string("hpav_slac.nmk_note",     "NMK Note")
local f_nid_note     = ProtoField.string("hpav_slac.nid_note",     "NID Note")

-- ECDH fields (Dylan's extension)
local f_ecdh_role        = ProtoField.string("hpav_slac.ecdh_role",        "Role")
local f_ecdh_curve       = ProtoField.string("hpav_slac.ecdh_curve",       "Elliptic Curve")
local f_ecdh_key_size    = ProtoField.string("hpav_slac.ecdh_key_size",    "Key Size")
local f_ecdh_pubkey      = ProtoField.bytes ("hpav_slac.ecdh_pubkey",      "EC Public Key (Uncompressed Point)")
local f_ecdh_pubkey_hex  = ProtoField.string("hpav_slac.ecdh_pubkey_hex",  "EC Public Key (hex)")
local f_ecdh_prefix      = ProtoField.string("hpav_slac.ecdh_prefix",      "Point Prefix")
local f_ecdh_x           = ProtoField.string("hpav_slac.ecdh_x",           "X Coordinate (hex)")
local f_ecdh_y           = ProtoField.string("hpav_slac.ecdh_y",           "Y Coordinate (hex)")
local f_ecdh_nmk_derive  = ProtoField.string("hpav_slac.ecdh_nmk_derive",  "NMK Derivation")
local f_ecdh_security    = ProtoField.string("hpav_slac.ecdh_security",    "Security Analysis")
local f_ecdh_standard    = ProtoField.string("hpav_slac.ecdh_standard",    "Standard Reference")

-- IBE fields (Pairing-based research extension)
local f_ibe_title        = ProtoField.string("hpav_slac.ibe_title",        "Key Establishment Method")
local f_ibe_scheme       = ProtoField.string("hpav_slac.ibe_scheme",       "IBE Scheme")
local f_ibe_group        = ProtoField.string("hpav_slac.ibe_group",        "Pairing Group")
local f_ibe_assumption   = ProtoField.string("hpav_slac.ibe_assumption",   "Security Assumption")
local f_ibe_pkg          = ProtoField.string("hpav_slac.ibe_pkg",          "PKG (Private Key Generator)")
local f_ibe_ev_id        = ProtoField.string("hpav_slac.ibe_ev_id",        "EV Identity String")
local f_ibe_evse_id      = ProtoField.string("hpav_slac.ibe_evse_id",      "EVSE Identity String")
local f_ibe_ev_key       = ProtoField.string("hpav_slac.ibe_ev_key",       "EV Private Key")
local f_ibe_evse_key     = ProtoField.string("hpav_slac.ibe_evse_key",     "EVSE Private Key")
local f_ibe_pairing      = ProtoField.string("hpav_slac.ibe_pairing",      "Bilinear Pairing")
local f_ibe_shared       = ProtoField.string("hpav_slac.ibe_shared",       "Shared Secret")
local f_ibe_nmk_derive   = ProtoField.string("hpav_slac.ibe_nmk_derive",   "NMK Derivation")
local f_ibe_wire         = ProtoField.string("hpav_slac.ibe_wire",         "Wire Transmission")
local f_ibe_vs_ecdh      = ProtoField.string("hpav_slac.ibe_vs_ecdh",      "Comparison vs ECDH")
local f_ibe_contribution = ProtoField.string("hpav_slac.ibe_contribution", "Research Contribution")

slac_proto.fields = {
    f_mmtype, f_mmtype_name, f_mmv, f_src_mac, f_dst_mac,
    f_direction, f_session_note,
    f_setkey_nmk, f_setkey_note,
    f_run_id, f_app_type, f_sec_type,
    f_num_sounds, f_timeout, f_resp_type,
    f_atten_avg, f_num_groups, f_atten_note,
    f_pev_mac, f_evse_mac, f_match_result, f_nmk_note, f_nid_note,
    f_ecdh_role, f_ecdh_curve, f_ecdh_key_size,
    f_ecdh_pubkey, f_ecdh_pubkey_hex, f_ecdh_prefix, f_ecdh_x, f_ecdh_y,
    f_ecdh_nmk_derive, f_ecdh_security, f_ecdh_standard,
    f_ibe_title, f_ibe_scheme, f_ibe_group, f_ibe_assumption,
    f_ibe_pkg, f_ibe_ev_id, f_ibe_evse_id,
    f_ibe_ev_key, f_ibe_evse_key, f_ibe_pairing, f_ibe_shared,
    f_ibe_nmk_derive, f_ibe_wire, f_ibe_vs_ecdh, f_ibe_contribution,
}

-- ── Helper: MAC bytes to string ──────────────────────────────
local function mac_str(buf, offset)
    return string.format("%02x:%02x:%02x:%02x:%02x:%02x",
        buf(offset,1):uint(),   buf(offset+1,1):uint(),
        buf(offset+2,1):uint(), buf(offset+3,1):uint(),
        buf(offset+4,1):uint(), buf(offset+5,1):uint())
end

-- ── Helper: bytes to hex string ──────────────────────────────
local function bytes_to_hex(buf, offset, len)
    local s = ""
    for i = 0, len-1 do
        s = s .. string.format("%02x", buf(offset+i,1):uint())
    end
    return s
end

-- ── Main dissector function ──────────────────────────────────
function slac_proto.dissector(buffer, pinfo, tree)
    if buffer:len() < 17 then return end

    -- Only handle HomePlug AV ethertype 0x88e1
    local eth_type = buffer(12,2):uint()
    if eth_type ~= 0x88e1 then return end

    local mm_type = buffer(15,2):le_uint()
    local src_mac = mac_str(buffer, 6)
    local dst_mac = mac_str(buffer, 0)

    -- ── CM_SET_KEY.REQ (0x6008) ─────────────────────────────
    if mm_type == 0x6008 then
        pinfo.cols.protocol:set("HomePlug-SLAC")
        pinfo.cols.info:set("CM_SET_KEY.REQ  [EVSE -> PLC Chip] NMK + NID programmed into QCA7000")
        local t = tree:add(slac_proto, buffer(), "HomePlug AV SLAC — CM_SET_KEY.REQ")
        t:add(f_mmtype,      buffer(15,2), mm_type):append_text("  (CM_SET_KEY.REQ)")
        t:add(f_mmtype_name, buffer(15,2), "CM_SET_KEY.REQ — Set Network Membership Key")
        t:add(f_src_mac,     buffer(6,6),  src_mac)
        t:add(f_dst_mac,     buffer(0,6),  dst_mac)
        t:add(f_direction,   buffer(6,6),  "EVSE-HLE -> Local QCA7000 PLC Chip (00:b0:52:00:00:01)")
        local k = t:add(slac_proto, buffer(), "Key Registration Details")
        k:add(f_setkey_nmk,  buffer(15,2), "New 16-byte NMK (Network Membership Key) written to chip")
        k:add(f_setkey_note, buffer(15,2), "This initializes the PLC logical network — all subsequent SLAC frames travel over this encrypted PLC channel")

    -- ── CM_SET_KEY.CNF (0x6009) ─────────────────────────────
    elseif mm_type == 0x6009 then
        pinfo.cols.protocol:set("HomePlug-SLAC")
        pinfo.cols.info:set("CM_SET_KEY.CNF  [PLC Chip -> EVSE] QCA7000 confirmed NMK registration")
        local t = tree:add(slac_proto, buffer(), "HomePlug AV SLAC — CM_SET_KEY.CNF")
        t:add(f_mmtype,      buffer(15,2), mm_type):append_text("  (CM_SET_KEY.CNF)")
        t:add(f_mmtype_name, buffer(15,2), "CM_SET_KEY.CNF — NMK Registration Confirmed")
        t:add(f_src_mac,     buffer(6,6),  src_mac)
        t:add(f_dst_mac,     buffer(0,6),  dst_mac)
        t:add(f_direction,   buffer(6,6),  "Local QCA7000 PLC Chip -> EVSE-HLE")
        t:add(f_setkey_note, buffer(15,2), "PLC chip acknowledged NMK — EVSE now waits for EV to initiate SLAC")

    -- ── CM_SLAC_PARM.REQ (0x6064) ───────────────────────────
    elseif mm_type == 0x6064 then
        pinfo.cols.protocol:set("HomePlug-SLAC")
        pinfo.cols.info:set("CM_SLAC_PARM.REQ  [EV -> Broadcast] EV initiates SLAC parameter exchange")
        local t = tree:add(slac_proto, buffer(), "HomePlug AV SLAC — CM_SLAC_PARM.REQ")
        t:add(f_mmtype,      buffer(15,2), mm_type):append_text("  (CM_SLAC_PARM.REQ)")
        t:add(f_mmtype_name, buffer(15,2), "CM_SLAC_PARM.REQ — SLAC Parameter Request")
        t:add(f_src_mac,     buffer(6,6),  src_mac)
        t:add(f_dst_mac,     buffer(0,6),  "ff:ff:ff:ff:ff:ff (Broadcast)")
        t:add(f_direction,   buffer(6,6),  "EV-HLE -> Broadcast (all EVSEs on PLC network)")
        local p = t:add(slac_proto, buffer(), "SLAC Parameters")
        p:add(f_app_type,    buffer(19,1), "0x00 — PEV-EVSE Matching")
        p:add(f_sec_type,    buffer(20,1), "0x00 — No Security (key exchange handled separately)")
        if buffer:len() >= 28 then
            p:add(f_run_id,  buffer(21,8))
        end
        t:add(f_session_note, buffer(15,2), "Step 1 of SLAC: EV broadcasts its presence — EVSE must respond within TT_EVSE_SLAC_init (20-50s)")

    -- ── CM_SLAC_PARM.CNF (0x6065) ───────────────────────────
    elseif mm_type == 0x6065 then
        pinfo.cols.protocol:set("HomePlug-SLAC")
        pinfo.cols.info:set("CM_SLAC_PARM.CNF  [EVSE -> EV] EVSE confirms SLAC parameters — session established")
        local t = tree:add(slac_proto, buffer(), "HomePlug AV SLAC — CM_SLAC_PARM.CNF")
        t:add(f_mmtype,      buffer(15,2), mm_type):append_text("  (CM_SLAC_PARM.CNF)")
        t:add(f_mmtype_name, buffer(15,2), "CM_SLAC_PARM.CNF — SLAC Parameter Confirmation")
        t:add(f_src_mac,     buffer(6,6),  src_mac)
        t:add(f_dst_mac,     buffer(0,6),  dst_mac)
        t:add(f_direction,   buffer(6,6),  "EVSE-HLE -> EV-HLE (Unicast)")
        t:add(f_session_note, buffer(15,2), "Step 2 of SLAC: EVSE responds to EV — SLAC session now active, attenuation measurement begins")

    -- ── CM_START_ATTEN_CHAR.IND (0x606a) ────────────────────
    elseif mm_type == 0x606a or mm_type == 0x6068 then
        pinfo.cols.protocol:set("HomePlug-SLAC")
        pinfo.cols.info:set("CM_START_ATTEN_CHAR.IND  [EV -> Broadcast] EV announces attenuation measurement start")
        local t = tree:add(slac_proto, buffer(), "HomePlug AV SLAC — CM_START_ATTEN_CHAR.IND")
        t:add(f_mmtype,      buffer(15,2), mm_type):append_text("  (CM_START_ATTEN_CHAR.IND)")
        t:add(f_mmtype_name, buffer(15,2), "CM_START_ATTEN_CHAR.IND — Start Attenuation Characterization")
        t:add(f_src_mac,     buffer(6,6),  src_mac)
        t:add(f_dst_mac,     buffer(0,6),  "ff:ff:ff:ff:ff:ff (Broadcast)")
        t:add(f_direction,   buffer(6,6),  "EV-HLE -> Broadcast")
        local p = t:add(slac_proto, buffer(), "Attenuation Parameters")
        if buffer:len() >= 22 then
            p:add(f_num_sounds, buffer(21,1), tostring(buffer(21,1):uint()) .. " MNBC sound bursts to follow")
            p:add(f_timeout,    buffer(22,1), tostring(buffer(22,1):uint() * 100) .. " ms total measurement window")
            p:add(f_resp_type,  buffer(23,1), "0x01 — Other GP Stations collect attenuation data")
        end
        t:add(f_session_note, buffer(15,2), "Step 3 of SLAC: EV notifies all GP stations that sound bursts are coming for signal measurement")

    -- ── CM_MNBC_SOUND.IND (0x6076) ──────────────────────────
    elseif mm_type == 0x6076 or mm_type == 0x6074 then
        pinfo.cols.protocol:set("HomePlug-SLAC")
        pinfo.cols.info:set("CM_MNBC_SOUND.IND  [EV -> Broadcast] EV transmits sound burst for PLC signal measurement")
        local t = tree:add(slac_proto, buffer(), "HomePlug AV SLAC — CM_MNBC_SOUND.IND")
        t:add(f_mmtype,      buffer(15,2), mm_type):append_text("  (CM_MNBC_SOUND.IND)")
        t:add(f_mmtype_name, buffer(15,2), "CM_MNBC_SOUND.IND — MNBC Sound Indication")
        t:add(f_src_mac,     buffer(6,6),  src_mac)
        t:add(f_dst_mac,     buffer(0,6),  "ff:ff:ff:ff:ff:ff (Broadcast)")
        t:add(f_direction,   buffer(6,6),  "EV-HLE -> Broadcast")
        local p = t:add(slac_proto, buffer(), "Sound Details")
        if buffer:len() >= 38 then
            p:add(f_num_sounds, buffer(36,1), "Remaining sounds: " .. tostring(buffer(36,1):uint()))
        end
        t:add(f_session_note, buffer(15,2), "Step 4 of SLAC: QCA7000 PLC chip measures signal attenuation per frequency group and reports via CM_ATTEN_PROFILE.IND")

    -- ── CM_ATTEN_PROFILE.IND (0x6086) ───────────────────────
    elseif mm_type == 0x6086 or mm_type == 0x6084 then
        pinfo.cols.protocol:set("HomePlug-SLAC")
        pinfo.cols.info:set("CM_ATTEN_PROFILE.IND  [PLC Chip -> EVSE] QCA7000 reports per-group attenuation measurements")
        local t = tree:add(slac_proto, buffer(), "HomePlug AV SLAC — CM_ATTEN_PROFILE.IND")
        t:add(f_mmtype,      buffer(15,2), mm_type):append_text("  (CM_ATTEN_PROFILE.IND)")
        t:add(f_mmtype_name, buffer(15,2), "CM_ATTEN_PROFILE.IND — Attenuation Profile Indication")
        t:add(f_src_mac,     buffer(6,6),  src_mac)
        t:add(f_dst_mac,     buffer(0,6),  dst_mac)
        t:add(f_direction,   buffer(6,6),  "Local QCA7000 PLC Chip -> EVSE-HLE")
        local p = t:add(slac_proto, buffer(), "Measurement Details")
        if buffer:len() >= 21 then
            p:add(f_num_groups, buffer(25,1), tostring(buffer(25,1):uint()) .. " frequency groups measured")
        end
        t:add(f_atten_note,  buffer(15,2), "Raw per-group attenuation values (AAG) — EVSE accumulates these across all sounds then averages")

    -- ── CM_ATTEN_CHAR.IND (0x606e) ──────────────────────────
    elseif mm_type == 0x606e or mm_type == 0x606c then
        pinfo.cols.protocol:set("HomePlug-SLAC")
        pinfo.cols.info:set("CM_ATTEN_CHAR.IND  [EVSE -> EV] EVSE sends averaged attenuation profile to EV")
        local t = tree:add(slac_proto, buffer(), "HomePlug AV SLAC — CM_ATTEN_CHAR.IND")
        t:add(f_mmtype,      buffer(15,2), mm_type):append_text("  (CM_ATTEN_CHAR.IND)")
        t:add(f_mmtype_name, buffer(15,2), "CM_ATTEN_CHAR.IND — Attenuation Characterization Indication")
        t:add(f_src_mac,     buffer(6,6),  src_mac)
        t:add(f_dst_mac,     buffer(0,6),  dst_mac)
        t:add(f_direction,   buffer(6,6),  "EVSE-HLE -> EV-HLE (Unicast)")
        local p = t:add(slac_proto, buffer(), "Attenuation Result")
        -- Parse average attenuation from AAG fields (3 groups shown)
        if buffer:len() >= 90 then
            local aag1 = buffer(84,1):uint()
            local aag2 = buffer(85,1):uint()
            local aag3 = buffer(86,1):uint()
            local avg  = (aag1 + aag2 + aag3) / 3
            p:add(f_atten_avg,   buffer(84,3), string.format("%.2f dB (Groups: %d, %d, %d dB)", avg, aag1, aag2, aag3))
            p:add(f_num_groups,  buffer(83,1), tostring(buffer(83,1):uint()) .. " frequency groups")
        end
        t:add(f_session_note, buffer(15,2), "Step 5 of SLAC: EVSE sends averaged attenuation — EV compares against SLAC_LIMIT threshold to decide if this EVSE is close enough to match")

    -- ── CM_ATTEN_CHAR.RSP (0x606f) ──────────────────────────
    elseif mm_type == 0x606f then
        pinfo.cols.protocol:set("HomePlug-SLAC")
        pinfo.cols.info:set("CM_ATTEN_CHAR.RSP  [EV -> EVSE] EV acknowledges attenuation data — proceeding to key establishment")
        local t = tree:add(slac_proto, buffer(), "HomePlug AV SLAC — CM_ATTEN_CHAR.RSP")
        t:add(f_mmtype,      buffer(15,2), mm_type):append_text("  (CM_ATTEN_CHAR.RSP)")
        t:add(f_mmtype_name, buffer(15,2), "CM_ATTEN_CHAR.RSP — Attenuation Characterization Response")
        t:add(f_src_mac,     buffer(6,6),  src_mac)
        t:add(f_dst_mac,     buffer(0,6),  dst_mac)
        t:add(f_direction,   buffer(6,6),  "EV-HLE -> EVSE-HLE (Unicast)")
        if buffer:len() >= 70 then
            local result = buffer(69,1):uint()
            if result == 0 then
                t:add(f_match_result, buffer(69,1), "0x00 — SUCCESS: Attenuation within acceptable range")
            else
                t:add(f_match_result, buffer(69,1), string.format("0x%02x — FAILURE: Attenuation too high", result))
            end
        end
        t:add(f_session_note, buffer(15,2), "Step 6 of SLAC: EV confirms attenuation acceptable — next step is cryptographic key establishment")

    -- ── CM_ECDH_EXCHANGE.REQ (0x6080) — Dylan's ECDH ────────
    elseif mm_type == 0x6080 then
        pinfo.cols.protocol:set("HomePlug-ECDH")
        pinfo.cols.info:set("CM_ECDH_EXCHANGE.REQ  [EVSE -> EV] EVSE transmits EC public key — ECDH key exchange initiated")
        local t = tree:add(slac_proto, buffer(), "HomePlug AV SLAC — CM_ECDH_EXCHANGE.REQ  [Dylan's ECDH Extension]")
        t:add(f_mmtype,       buffer(15,2), mm_type):append_text("  (CM_ECDH_EXCHANGE.REQ — Custom, not in ISO 15118-3)")
        t:add(f_mmtype_name,  buffer(15,2), "CM_ECDH_EXCHANGE.REQ — Elliptic Curve Diffie-Hellman Exchange Request")
        t:add(f_src_mac,      buffer(6,6),  src_mac)
        t:add(f_dst_mac,      buffer(0,6),  dst_mac)
        t:add(f_direction,    buffer(6,6),  "EVSE-HLE -> EV-HLE (Unicast)")
        t:add(f_ecdh_role,    buffer(6,6),  "EVSE — sends its EC public key (Qc)")
        t:add(f_ecdh_standard,buffer(15,2), "Based on Baker 2019 proposal — not standardized in ISO 15118-3")

        -- Decode the EC public key
        local key_t = t:add(slac_proto, buffer(), "EVSE EC Public Key (Qc)")
        key_t:add(f_ecdh_curve,    buffer(15,2), "SECP192R1 — 192-bit prime field elliptic curve (NIST P-192)")
        key_t:add(f_ecdh_key_size, buffer(15,2), "49 bytes (1 byte prefix + 24 bytes X + 24 bytes Y)")
        if buffer:len() >= 68 then
            local key = buffer(19, 49)
            key_t:add(f_ecdh_pubkey,    key)
            key_t:add(f_ecdh_pubkey_hex,key, key:bytes():tohex())
            -- Decode prefix and coordinates
            local prefix = buffer(19,1):uint()
            if prefix == 0x04 then
                key_t:add(f_ecdh_prefix, buffer(19,1), "0x04 — Uncompressed point format")
            end
            if buffer:len() >= 68 then
                key_t:add(f_ecdh_x, buffer(20,24), bytes_to_hex(buffer, 20, 24) .. " (X coordinate)")
                key_t:add(f_ecdh_y, buffer(44,24), bytes_to_hex(buffer, 44, 24) .. " (Y coordinate)")
            end
        end

        -- Security analysis
        local sec_t = t:add(slac_proto, buffer(), "ECDH Security Analysis")
        sec_t:add(f_ecdh_nmk_derive, buffer(15,2), "NMK = SHA256(shared_secret)[:16]  where shared_secret = ECDH(SK_EVSE, PK_EV)")
        sec_t:add(f_ecdh_security,   buffer(15,2), "PUBLIC KEY IS VISIBLE ON WIRE — an attacker capturing this frame sees the EVSE public key")
        sec_t:add(f_ecdh_security,   buffer(15,2), "Security relies on Elliptic Curve Discrete Logarithm Problem (ECDLP) — cannot derive private key from public key")
        t:add(f_session_note, buffer(15,2), "Step 7a of SLAC+ECDH: EVSE sends its public key — EV must respond with its public key to complete ECDH")

    -- ── CM_ECDH_EXCHANGE.RSP (0x6083) — Dylan's ECDH ────────
    elseif mm_type == 0x6083 then
        pinfo.cols.protocol:set("HomePlug-ECDH")
        pinfo.cols.info:set("CM_ECDH_EXCHANGE.RSP  [EV -> EVSE] EV transmits EC public key — ECDH shared secret derivable by both sides")
        local t = tree:add(slac_proto, buffer(), "HomePlug AV SLAC — CM_ECDH_EXCHANGE.RSP  [Dylan's ECDH Extension]")
        t:add(f_mmtype,       buffer(15,2), mm_type):append_text("  (CM_ECDH_EXCHANGE.RSP — Custom, not in ISO 15118-3)")
        t:add(f_mmtype_name,  buffer(15,2), "CM_ECDH_EXCHANGE.RSP — Elliptic Curve Diffie-Hellman Exchange Response")
        t:add(f_src_mac,      buffer(6,6),  src_mac)
        t:add(f_dst_mac,      buffer(0,6),  dst_mac)
        t:add(f_direction,    buffer(6,6),  "EV-HLE -> EVSE-HLE (Unicast)")
        t:add(f_ecdh_role,    buffer(6,6),  "EV — sends its EC public key (Qv)")
        t:add(f_ecdh_standard,buffer(15,2), "Based on Baker 2019 proposal — not standardized in ISO 15118-3")

        -- Decode the EC public key
        local key_t = t:add(slac_proto, buffer(), "EV EC Public Key (Qv)")
        key_t:add(f_ecdh_curve,    buffer(15,2), "SECP192R1 — 192-bit prime field elliptic curve (NIST P-192)")
        key_t:add(f_ecdh_key_size, buffer(15,2), "49 bytes (1 byte prefix + 24 bytes X + 24 bytes Y)")
        if buffer:len() >= 68 then
            local key = buffer(19, 49)
            key_t:add(f_ecdh_pubkey,    key)
            key_t:add(f_ecdh_pubkey_hex,key, key:bytes():tohex())
            local prefix = buffer(19,1):uint()
            if prefix == 0x04 then
                key_t:add(f_ecdh_prefix, buffer(19,1), "0x04 — Uncompressed point format")
            end
            if buffer:len() >= 68 then
                key_t:add(f_ecdh_x, buffer(20,24), bytes_to_hex(buffer, 20, 24) .. " (X coordinate)")
                key_t:add(f_ecdh_y, buffer(44,24), bytes_to_hex(buffer, 44, 24) .. " (Y coordinate)")
            end
        end

        -- Security analysis
        local sec_t = t:add(slac_proto, buffer(), "ECDH Security Analysis")
        sec_t:add(f_ecdh_nmk_derive, buffer(15,2), "NMK = SHA256(shared_secret)[:16]  where shared_secret = ECDH(SK_EV, PK_EVSE)")
        sec_t:add(f_ecdh_security,   buffer(15,2), "PUBLIC KEY IS VISIBLE ON WIRE — both public keys (frames 0x6080 and 0x6083) are observable")
        sec_t:add(f_ecdh_security,   buffer(15,2), "Forward secrecy: new keypair generated per session — compromise of one session does not reveal others")
        t:add(f_session_note, buffer(15,2), "Step 7b of SLAC+ECDH: Both public keys now exchanged — each side independently computes same NMK via ECDH math")

    -- ── CM_SLAC_MATCH.REQ (0x607c) ──────────────────────────
    elseif mm_type == 0x607c then
        pinfo.cols.protocol:set("HomePlug-SLAC")
        pinfo.cols.info:set("CM_SLAC_MATCH.REQ  [EV -> EVSE] EV requests final SLAC network matching")
        local t = tree:add(slac_proto, buffer(), "HomePlug AV SLAC — CM_SLAC_MATCH.REQ")
        t:add(f_mmtype,      buffer(15,2), mm_type):append_text("  (CM_SLAC_MATCH.REQ)")
        t:add(f_mmtype_name, buffer(15,2), "CM_SLAC_MATCH.REQ — SLAC Match Request")
        t:add(f_src_mac,     buffer(6,6),  src_mac)
        t:add(f_dst_mac,     buffer(0,6),  dst_mac)
        t:add(f_direction,   buffer(6,6),  "EV-HLE -> EVSE-HLE (Unicast)")

        -- Parse PEV and EVSE MAC from payload
        if buffer:len() >= 60 then
            local ids_t = t:add(slac_proto, buffer(), "Session Identifiers")
            ids_t:add(f_pev_mac,  buffer(41,6), mac_str(buffer, 41))
            ids_t:add(f_evse_mac, buffer(64,6), mac_str(buffer, 64))
            if buffer:len() >= 78 then
                ids_t:add(f_run_id, buffer(70,8))
            end
        end

        -- IBE annotation subtree
        local ibe_t = t:add(slac_proto, buffer(), "IBE Key Establishment — Non-Interactive Pairing-Based (Research Extension)")
        ibe_t:add(f_ibe_title,        buffer(15,2), "Identity-Based Encryption (IBE) via Bilinear Pairing — replaces ECDH")
        ibe_t:add(f_ibe_scheme,       buffer(15,2), "Boneh-Franklin IBE (2001) — foundational pairing-based IBE scheme")
        ibe_t:add(f_ibe_group,        buffer(15,2), "SS512 — Symmetric Type-A pairing group over 512-bit field")
        ibe_t:add(f_ibe_assumption,   buffer(15,2), "Security based on Bilinear Diffie-Hellman (BDH) assumption")
        ibe_t:add(f_ibe_pkg,          buffer(15,2), "PKG (Private Key Generator) runs on PC — holds master secret s, generates board private keys")

        local id_t = ibe_t:add(slac_proto, buffer(), "Identity Strings (MAC-based)")
        id_t:add(f_ibe_ev_id,         buffer(6,6),  "EV:88fca61c81c2   (derived from EV MAC address " .. mac_str(buffer, 6) .. ")")
        id_t:add(f_ibe_evse_id,       buffer(0,6),  "EVSE:88fca61c81bb (derived from EVSE MAC address " .. mac_str(buffer, 0) .. ")")

        local key_t = ibe_t:add(slac_proto, buffer(), "Private Key Extraction (PKG Operation)")
        key_t:add(f_ibe_ev_key,       buffer(15,2), "SK_EV   = s * H('EV:88fca61c81c2')   where s = master secret, H = hash-to-G1")
        key_t:add(f_ibe_evse_key,     buffer(15,2), "SK_EVSE = s * H('EVSE:88fca61c81bb') where s = master secret, H = hash-to-G1")

        local math_t = ibe_t:add(slac_proto, buffer(), "Bilinear Pairing Key Agreement")
        math_t:add(f_ibe_pairing,     buffer(15,2), "EV   computes: e(SK_EV,   Q_EVSE) = e(s*H(ID_EV),   H(ID_EVSE))")
        math_t:add(f_ibe_pairing,     buffer(15,2), "EVSE computes: e(SK_EVSE, Q_EV)   = e(s*H(ID_EVSE), H(ID_EV))")
        math_t:add(f_ibe_shared,      buffer(15,2), "By bilinearity: e(s*H(ID_EV), H(ID_EVSE)) == e(s*H(ID_EVSE), H(ID_EV)) — SAME VALUE")
        math_t:add(f_ibe_nmk_derive,  buffer(15,2), "NMK = SHA256(shared_pairing_element || 'SLAC-IBE-NMK-v1' || run_id || ID_EV || ID_EVSE)[:16]")

        local wire_t = ibe_t:add(slac_proto, buffer(), "Wire Security Comparison")
        wire_t:add(f_ibe_wire,        buffer(15,2), "IBE: ZERO cryptographic frames on wire — private keys and shared secret never transmitted")
        wire_t:add(f_ibe_vs_ecdh,     buffer(15,2), "ECDH: 2 frames on wire (0x6080 REQ + 0x6083 RSP) — public keys visible to any sniffer")
        wire_t:add(f_ibe_contribution,buffer(15,2), "RESEARCH CONTRIBUTION: Non-interactive IBE eliminates key exchange overhead and removes observable key material from PLC wire")

        t:add(f_session_note, buffer(15,2), "Step 7 of SLAC+IBE: Key establishment already completed locally — no network traffic generated — this frame initiates final matching")

    -- ── CM_SLAC_MATCH.CNF (0x607d) ──────────────────────────
    elseif mm_type == 0x607d then
        pinfo.cols.protocol:set("HomePlug-SLAC")
        pinfo.cols.info:set("CM_SLAC_MATCH.CNF  [EVSE -> EV] SLAC MATCHED — PLC logical network established — HLC charging ready")
        local t = tree:add(slac_proto, buffer(), "HomePlug AV SLAC — CM_SLAC_MATCH.CNF  [SESSION ESTABLISHED]")
        t:add(f_mmtype,       buffer(15,2), mm_type):append_text("  (CM_SLAC_MATCH.CNF)")
        t:add(f_mmtype_name,  buffer(15,2), "CM_SLAC_MATCH.CNF — SLAC Match Confirmation — HANDSHAKE COMPLETE")
        t:add(f_src_mac,      buffer(6,6),  src_mac)
        t:add(f_dst_mac,      buffer(0,6),  dst_mac)
        t:add(f_direction,    buffer(6,6),  "EVSE-HLE -> EV-HLE (Unicast)")
        t:add(f_match_result, buffer(15,2), "SUCCESS — EV and EVSE are now in the same HomePlug logical network")

        local nmk_t = t:add(slac_proto, buffer(), "NMK / NID Details")
        nmk_t:add(f_nmk_note, buffer(15,2), "NMK field in this frame = 0x000...000 (16 zero bytes) — intentionally blank per ISO 15118-3")
        nmk_t:add(f_nmk_note, buffer(15,2), "Real NMK was derived independently by both sides via IBE pairing — never transmitted")
        nmk_t:add(f_nid_note, buffer(15,2), "NID (Network ID) derived from NMK via generate_nid() — identifies the logical PLC network")

        local result_t = t:add(slac_proto, buffer(), "Protocol Completion Summary")
        result_t:add(f_session_note, buffer(15,2), "SLAC complete: EV and EVSE share same NMK — QCA7000 PLC chips can now communicate as one logical network")
        result_t:add(f_session_note, buffer(15,2), "Next: ISO 15118-2 HLC (High Level Communication) over IPv6/TCP begins for actual charging negotiation")
        result_t:add(f_session_note, buffer(15,2), "PLC LED on devolo boards: solid green = matched, this confirms physical PLC link is established")

    end
end

-- ── Register as post-dissector ───────────────────────────────
-- This runs AFTER the built-in HomePlug dissector
-- so our labels override the Protocol and Info columns
register_postdissector(slac_proto)

print("[SLAC Dissector v2.0] Loaded successfully")
print("[SLAC Dissector] Covers: SET_KEY, SLAC_PARM, ATTEN_CHAR, MNBC_SOUND, ATTEN_PROFILE, ECDH_EXCHANGE, IBE, SLAC_MATCH")
print("[SLAC Dissector] Protocol labels: HomePlug-SLAC, HomePlug-ECDH")
