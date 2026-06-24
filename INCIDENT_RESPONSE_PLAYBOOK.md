# Incident Response Playbook — JDY Botnet

A field handbook for responding to a suspected JDY compromise. Written for responders working
a live incident: triage, scope, contain, eradicate, recover, with decision points and
evidence-collection checklists throughout.

**Read this first:** JDY is a **reconnaissance and prepositioning** capability on **edge /
SOHO devices**. The implant is findable; the hard part is that the actor's stealth lives on
the **victim's device** using living-off-the-land techniques, and the relay layer it talks to
is disposable. Your objective is to confirm, scope, evict, and harden — not to chase rotating
relay IPs.

**Classification:** TLP:CLEAR · findings tagged NOVEL / CORROBORATED / PUBLISHED / EXCLUDED

> Companion documents: hunt logic in the [Threat Hunting Guide](THREAT_HUNTING_GUIDE.md);
> signals and IOCs in the [Tactical Intelligence Report](TACTICAL_INTELLIGENCE_REPORT.md);
> rules in [`../detections/`](../detections).

---

## 0. Before you touch anything — scope the posture

- **This is a passive-defense incident.** Do not interact with the live JDY infrastructure
  (no probing relays, no fetching from C2 hostnames). Work from your own logs and from
  read-only scan data.
- **Preserve volatile state on edge devices first.** Many routers/firewalls lose all forensic
  state on reboot. Do **not** reboot a suspect edge device until volatile collection is done
  (Section 4) — a reboot can destroy the only evidence.
- **Assume the device, not just a process.** On edge gear the implant may be the whole story;
  there may be no "host EDR" to lean on. Plan for device-level forensics.

---

## 1. Incident lifecycle at a glance

```
DETECT -> TRIAGE -> SCOPE -> CONTAIN -> ERADICATE -> RECOVER -> POST-INCIDENT
   |         |        |         |           |           |            |
 signal   JDY vs    how many   stop the   remove the  restore &   lessons,
  fires   co-tenant  devices?  beacon &   implant,    re-trust    detections,
          (gate)               scanning   re-image    the device  reporting
```

---

## 2. Triage — confirm it is JDY

Run the disambiguation gate before declaring an incident. The cost of a false "JDY" is wasted
escalation; the cost of a false "noise" is a missed state-actor foothold. Be deliberate.

### 2.1 The JDY-vs-co-tenant decision tree

```
A device/connection looks suspicious.
│
├─ Outbound TLS to a host serving the jdyfj cert?  ───────────────► STRONG JDY  (go to Scope)
│   (SHA-256 2b640582…432cf / serial 0xab8f51eb48f363f1)
│
├─ A file on the device is the implant hash, or a MIPS64 BE ELF
│   carrying /usr/local/openssl/1.0.2u/mips64/ ?  ───────────────► STRONG JDY  (go to Scope)
│
├─ Outbound SYN scanning: source port 19000 AND an ascending ISN
│   run seeded at 0x3251d2d, no payload?  ──────────────────────► LIKELY JDY  (corroborate, then Scope)
│
├─ Only a single commodity selector?  (sport 19000 alone, "Acme Co"
│   alone, Platypus :13339 alone, JARM on common nginx)  ───────► NOT PROMOTABLE
│        └─ check false-positive population (the catalog). Thousands = commodity = EXCLUDE.
│
└─ A Windows PE "related" to the sample, or x86-sandbox "contacted IPs"? ─► EXCLUDE
         └─ architecturally impossible as a JDY sibling (implant is MIPS64 BE).
```

### 2.2 Triage checklist

- [ ] Identify the suspect asset(s) and their role (edge device? internal host? relay you host?).
- [ ] Pull the egress records for the suspect asset (NetFlow / firewall / proxy).
- [ ] Test against the **jdyfj cert** and the **cluster IPs** (leads, not proof — relays rotate).
- [ ] Look for the **behavioral** profile (seeded-ISN SYN run, `dispatch_service/v2/*` URIs).
- [ ] If a sample is recoverable, hash it and check for the **build path**.
- [ ] Apply the gate (2.1). Record the tag (STRONG / LIKELY / EXCLUDE) and the evidence.

---

## 3. Scope — how far has it spread

JDY is a fleet capability. One confirmed device implies a question, not a conclusion, about
the rest of the estate.

- [ ] **Enumerate all internet-facing edge devices** of the same make/model/firmware as the
      confirmed device — they share the likely initial-access vector.
- [ ] **Sweep egress** for any other internal asset beaconing to the cluster IPs or the
      jdyfj cert.
- [ ] **Sweep for the scanning profile** organization-wide (seeded-ISN SYN runs from any
      internal source).
- [ ] **Check for the relay role on your own estate** — is any host you own carrying the
      jdyfj cert or the paired payload-host profile (you may be hosting a relay, not just a bot).
- [ ] **Timeline the beacon.** First-seen of the outbound dispatch traffic bounds the
      compromise window; pull device logs back to that point.
- [ ] **Decrypt captured tasking if available** (Section 6) to learn what the bot was told to
      scan — this reveals the operator's current targeting and can indicate intent.

**Scope decision:** single device vs. fleet. If more than one device is confirmed, escalate to
a coordinated estate-wide response and treat edge-device firmware/credentials as compromised
class-wide.

---

## 4. Evidence collection (edge-device aware)

Collect **before** containment changes state, and **before** any reboot.

### 4.1 Volatile (collect first, device may wipe on reboot)

- [ ] Running processes / loaded modules (device CLI or equivalent).
- [ ] Active network connections and listening sockets.
- [ ] Current routing / firewall / NAT state.
- [ ] ARP and connection tables.
- [ ] In-memory configuration vs. on-disk configuration (look for runtime-only changes).

### 4.2 Network (your own captures and logs)

- [ ] Full egress records for the device across the compromise window.
- [ ] Any packet capture containing the dispatch traffic (the `probe_task` body, if present,
      is the encrypted tasking — preserve it for decryption).
- [ ] TLS metadata: the cert served by the contacted host (confirm jdyfj), SNI, JA3/JA4 if
      available.

### 4.3 Host / device

- [ ] The implant binary, if recoverable (hash it; check the build path; preserve for analysis).
- [ ] Persistence artifacts (startup scripts, cron-equivalents, modified firmware components).
- [ ] Account and credential state (edge devices are often compromised via weak/default creds).

### 4.4 Chain of custody

- [ ] Hash every collected artifact at collection time.
- [ ] Record collector, timestamp, source device, and method for each item.
- [ ] Keep captured tasking blobs intact (do not re-encode) so the decryptor sees the exact bytes.

---

## 5. Containment

Goal: stop the beacon and the scanning without tipping off the operator before you are ready
to evict, and without destroying evidence.

- [ ] **Block egress** from the confirmed device to the cluster IPs and to any host serving the
      jdyfj cert (egress filter at the perimeter).
- [ ] **Contain the scanning.** Restrict the device's ability to originate outbound SYN traffic
      to arbitrary destinations (segment / ACL).
- [ ] **Isolate, do not yet reboot.** Network-isolate the device so volatile evidence survives
      until collection is complete.
- [ ] **Preserve a monitoring window if scoping is incomplete.** If you still need to learn the
      blast radius, capturing the beacon a little longer (read-only) may be worth more than an
      immediate hard block — a judgment call for the IC.
- [ ] **Do not engage the relays.** Containment is on your side of the wire only.

**Containment decision:** immediate hard-block vs. brief monitored containment. Choose based on
whether scope is known and whether the device is critical/availability-sensitive.

---

## 6. Decryptor in the live-response flow

If you captured a tasking blob, decrypting it turns "a device was beaconing" into "here is
exactly what the operator told it to do."

```bash
# verify the tool wiring first (no input needed)
python3 tools/jdy_decrypt.py --selftest

# decrypt the captured probe_task / content body (base64 text)
python3 tools/jdy_decrypt.py captured_task.b64
```

**Interpreting the output.** The plaintext JSON contains `scan_type`, task IDs, and a target
`content` list (IP ranges, ports, CVE/fingerprint rules). Use it to:

- Understand **what the operator is currently targeting** (which may include your other assets).
- Corroborate the device's role and the compromise timeline.
- Inform scoping — if the tasking points at internal ranges, widen the sweep accordingly.

**If it fails the PKCS#7 check:** the input is almost certainly **not the raw AES blob** (HTTP
framing left on it, or the wrong field captured) — re-extract the exact response body. The
cipher is correct; suspect the input.

---

## 7. Eradication

- [ ] **Re-image / re-flash the device** to known-good firmware. On edge devices, assume the
      implant and any persistence cannot be reliably cleaned in place — rebuild.
- [ ] **Rotate all credentials** on the device and any credentials it could have exposed
      (management, VPN, shared secrets).
- [ ] **Patch the initial-access vulnerability** (firmware update) before returning the device
      to service.
- [ ] **Remove relay artifacts** if you hosted a relay (the jdyfj cert/service, the panel, the
      payload-host listeners) and rebuild that host from clean media.
- [ ] **Confirm the beacon is gone** — re-check egress after eradication; no `dispatch_service`
      traffic, no scanning profile.

---

## 8. Recovery and re-trust

- [ ] Return the device to service only after firmware is current, credentials are rotated, and
      egress is clean.
- [ ] **Monitor the recovered device** with elevated scrutiny for a defined period (re-infection
      via the same vector is the risk).
- [ ] **Validate detections** fire correctly against the now-known indicators in your environment.
- [ ] **Re-baseline** the edge estate's exposure (the incident is also a signal about class-wide
      device risk).

---

## 9. Communications and escalation

- **Escalate to leadership early** if any device is confirmed — Volt Typhoon-class activity is a
  strategic matter, not a routine malware cleanup. Use the
  [Strategic Intelligence Report](STRATEGIC_INTELLIGENCE_REPORT.md) framing for leadership.
- **Consider regulatory / national-CERT reporting obligations** for critical-infrastructure
  operators (align to CISA / NCSC guidance on China-nexus device networks).
- **Coordinate, do not broadcast.** Premature public disclosure of your specific indicators can
  tip the operator; share through trusted channels.
- **One disclosure note for any external sharing:** infrastructure indicators rotate — share
  technique and behavior, which last, over IP lists, which do not.

---

## 10. Pitfalls (learned the hard way)

- **Rebooting before volatile collection** destroys the only evidence on many edge devices.
- **Chasing relay IPs** wastes effort — they rotate; pivot on the cert and behavior instead.
- **Promoting co-tenancy** (shared ASN/provider, a single commodity selector) creates false
  incidents — run the gate.
- **Conflating JDY with the CVE-2026-35616 exploitation campaign** — JDY *scans* for that CVE;
  the EKZ Infostealer that *exploits* it is a separate actor. Do not merge the two responses.
- **Cleaning in place** on edge devices — assume rebuild, not disinfect.

---

*AI-assisted analysis; all guidance is leads for analyst reproduction. TLP:CLEAR.*
