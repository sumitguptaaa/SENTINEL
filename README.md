# SENTINEL

**Passive Intrusion Detection System for MAVLink Drone Communication Networks**

SENTINEL monitors MAVLink protocol traffic in real time, learns normal communication 
patterns, and raises structured alerts when anomalous behaviour is detected. It runs 
passively — no traffic injection, no interference with the drone's operation.

Built as part of the [VIMANA](https://github.com/sumitguptaaa) aerospace security 
research platform.

---

## What It Detects

| Rule | Category | Severity | Description |
|------|----------|----------|-------------|
| R1 | Unknown Source | HIGH | Command messages from unrecognised system IDs |
| R2 | Inflight DISARM | CRITICAL | DISARM command issued while vehicle is armed and airborne |
| R3 | Command Flood | HIGH | Command rate exceeds threshold — potential DoS |
| R4 | GPS Teleport | CRITICAL | Position jump implying physically impossible velocity |
| R5 | Replay Attack | MEDIUM | Duplicate MAVLink sequence number from same source |
| R6 | Param Manipulation | HIGH | PARAM_SET message from untrusted system ID |

---

## Architecture
```
MAVLink Traffic (UDP/Serial)
        │
        ▼
┌──────────────────┐
│   MAVCapture     │  ← Packet capture engine (threaded)
│   (capture.py)   │  ← Parses raw MAVLink into MAVPacket dataclass
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  RulesEngine     │  ← Learning phase (30s baseline)
│  (rules.py)      │  ← Analyses each packet against 6 rules
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Alert System    │  ← Structured JSON alerts with severity
│  + Console Output│  ← Colour-coded terminal output
└──────────────────┘
```

---

## Quick Start
```bash
# Clone and install
git clone https://github.com/sumitguptaaa/sentinel
cd sentinel
pip install -r requirements.txt

# Run against ArduPilot SITL
python sentinel/sentinel.py --connection udp:127.0.0.1:14550

# Run tests
pytest tests/ -v
```

---

## Project Structure
```
sentinel/
├── sentinel/
│   ├── core/
│   │   └── capture.py      # MAVPacket dataclass + MAVCapture engine
│   └── ids/
│       └── rules.py        # Alert, Severity, SentinelRulesEngine
├── sentinel.py             # Main coordinator + CLI
├── scripts/
│   ├── attack_inject.py    # Injects test attack traffic against SITL
│   └── evaluate.py         # Detection rate evaluation (TP/FP per rule)
├── tests/
│   └── test_rules.py       # 18+ unit tests (3 per rule minimum)
└── requirements.txt
```

---

## Detection Methodology

SENTINEL operates in two phases:

**Learning phase (first 30 seconds):** Passively observes traffic and builds a 
baseline of known system IDs, normal command rates, and position history. No 
alerts are raised during this phase.

**Detection phase:** Each incoming packet is analysed against all six rules using 
the learned baseline. Anomalies generate structured Alert objects with timestamp, 
rule name, severity, and a human-readable description.

This approach — baseline learning followed by anomaly detection against a 
communication stream — is architecturally identical to the pattern recognition 
methodology used in CDR and IPDR forensic analysis, applied to drone 
communication networks.

---

## Status

🔨 **Actively in development — March 2026**

- [x] Project structure
- [x] MAVPacket dataclass
- [x] MAVCapture engine
- [ ] All 6 detection rules (in progress)
- [ ] Attack injection scripts
- [ ] Evaluation framework
- [ ] Research paper

---

## Research Context

SENTINEL is the first component of **VIMANA** — an aerospace security research 
platform targeting vulnerabilities in civilian drone communication infrastructure. 
Subsequent components include ARGUS (distributed threat intelligence) and 
NAKSHATRA (GAGAN SBAS security analysis).

---

## Author

**Sumit Gupta**  
MCA Cybersecurity, Amity University  
sijsumitgupta@gmail.com  
[GitHub](https://github.com/sumitguptaaa)
