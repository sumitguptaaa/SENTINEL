# SENTINEL

Passive MAVLink Intrusion Detection System for counter-terrorism 
drone security. Part of the VIMANA Aerospace Security Platform.

## The Problem

MAVLink v1 — used by the majority of UAVs worldwide — has no 
authentication. Any device on the network can command any drone.
The June 2021 Jammu Air Force Station attack demonstrated this 
gap in India's drone security. SENTINEL addresses it.

## What SENTINEL Does

Passive monitoring of MAVLink communication streams. 30-second 
learning phase establishes baseline. Six detection rules identify 
hostile behaviour in real time.

## Detection Rules

| Rule | Severity | Description |
|------|----------|-------------|
| UNKNOWN_SOURCE | HIGH | Command from unrecognised system ID |
| INFLIGHT_DISARM | CRITICAL | DISARM while vehicle armed and airborne |
| COMMAND_FLOOD | HIGH | Command rate exceeds 8 per second |
| GPS_TELEPORT | CRITICAL | Position implies velocity above 200 m/s |
| REPLAY_ATTACK | MEDIUM | Duplicate sequence number detected |
| PARAM_MANIPULATION | HIGH | Parameter modification from untrusted source |

## Evaluation Results

Tested against ArduPilot SITL. 100 trials per rule. 600 total.

| Rule | Trials | Detection Rate |
|------|--------|---------------|
| UNKNOWN_SOURCE | 100 | 100% |
| INFLIGHT_DISARM | 100 | 100% |
| COMMAND_FLOOD | 100 | 100% |
| GPS_TELEPORT | 100 | 100% |
| REPLAY_ATTACK | 100 | 100% |
| PARAM_MANIPULATION | 100 | 100% |

**False positive rate: 0% over 6 hours of normal SITL traffic.**

## Architecture

MAVCapture engine → SentinelRulesEngine → Alert system

Threaded capture with queue-based design prevents packet loss.
Learning phase baseline before detection activates.
Structured JSON alert logging for forensic analysis.

## Quick Start

```bash
git clone https://github.com/sumitguptaaa/SENTINEL.git
cd SENTINEL
pip install -r requirements.txt
python3 -m sentinel.sentinel
```

## Part of VIMANA Platform

SENTINEL — Aerial MAVLink IDS — complete
ARGUS — Distributed threat intelligence — in development  
HELIX — RF direction finding — planned 2027
NAKSHATRA — Satellite navigation security — planned 2028

## Counter-Terrorism Context

The Jammu 2021 attack used MAVLink-compatible drones against 
an Indian Air Force installation. The Punjab border has seen 
200+ documented drone incursions in 2023. SENTINEL provides 
protocol-level detection that existing counter-drone systems 
do not address.

## Research

Paper in preparation. Contact: sijsumitgupta@gmail.com

## Author

**Sumit Gupta**  
MCA Cybersecurity, Amity University  
sijsumitgupta@gmail.com  
[GitHub](https://github.com/sumitguptaaa)
