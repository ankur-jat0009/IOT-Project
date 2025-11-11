# Design and Evaluation of a Hash-Based Mitigation (DRM) for RPL DIO Replay Attacks in ns-3

### Course: CS366 - Internet of Things  
### National Institute of Technology Karnataka, Surathkal  
**Authors:**  
- Rishabh Mahor (221CS229)
- Harsha J G (221CS222)
- Divyanshu Surti (221CS157)
- Ankur Jat (221CS208)
**Date:** November 11, 2025  

---

## Project Overview

RPL (Routing Protocol for Low-Power and Lossy Networks) is widely used in IoT devices but is vulnerable to **DIO Replay Attacks**, where an attacker repeatedly rebroadcasts old DIO messages to overload nodes and disrupt network topology.

This project implements a **lightweight, hash-based Detection and Response Module (DRM)** in ns-3 to detect and mitigate DIO replay attacks **without using heavy cryptography**, making it suitable for constrained IoT devices.

---

## Key Features of the DRM

| Security Component | Description |
|--------------------|--------------|
| CRC16 Hashing | Creates a 2-byte lightweight fingerprint of DIO packets |
| Stateful Neighbor Cache | Stores last 8 unique DIO hashes per neighbor |
| Duplicate Detection | Detects repeated hashes from same sender |
| Cross-Source Replay Detection | Detects stolen DIOs replayed by attackers |
| Blacklisting | Blocks malicious nodes for 60 seconds |
| Low Overhead | No cryptography used, memory & CPU friendly |

---

## Simulation Setup (ns-3)

- **Topology:** 20 static nodes in a 5x4 grid
- **Communication:** Wi-Fi Ad-Hoc (OFDM - 6 Mbps)
- **Applications running:**
  - Root Node → broadcasts DIO every 5 seconds
  - Attacker Node → captures & replays DIO at 5 packets/sec
  - All Nodes → DRM component installed
- **Attack Start Time:** 12s into the simulation
- **Scenarios Tested:**
  1. Baseline (Mitigation OFF)
  2. Protected (Mitigation ON)

---

## Results Summary

| Evaluation Metric | Baseline (OFF) | Protected (ON) |
|-------------------|----------------|----------------|
| DIOs dropped due to mitigation | 0 | 99 |
| Total suspicious events | 0 | 27 |
| Total blacklist events | 0 | 2 |
| Detection time | ❌ NONE | ✅ 51.0001s |

 **DRM successfully detected and mitigated the replay attack**, protecting network stability and reducing overhead.

---

## File Structure

```

📁 drm-rpl-replay-attack-ns3
│
├── dio.cc                 # Main simulation code with DRM, Attacker & Root apps
├── README.md              # Documentation (this file)
└── report/                # LaTeX Report (optional to include)
└── report.tex

````

---

## How to Run

### Step 1: Copy `dio.cc` into ns-3 `scratch/` directory

```bash
cp dio.cc ns-3.xx/scratch/
````

### Step 2: Build

```bash
./waf build
```

### Step 3: Execute Simulation

#### Run with Mitigation Enabled (Protected Scenario)

```bash
./waf --run "scratch/dio --disableRootProtection=false --simTime=80 --attackStart=12 --attackerRate=5"
```

#### Run with Mitigation Disabled (Baseline Scenario)

```bash
./waf --run "scratch/dio --disableRootProtection=true --simTime=80 --attackStart=12 --attackerRate=5"
```

---

## Command Line Arguments

| Argument                  | Description                   | Default |
| ------------------------- | ----------------------------- | ------- |
| `--disableRootProtection` | Enables/Disables DRM          | true    |
| `--nNodes`                | Number of nodes               | 20      |
| `--attackerRate`          | Attack replay rate (pkts/sec) | 5       |
| `--attackStart`           | Time attack starts            | 12s     |
| `--simTime`               | Total simulation time         | 60s     |

Example:

```bash
./waf --run "scratch/dio --nNodes=30 --attackerRate=8 --disableRootProtection=false"
```

---

## Report

A detailed project report including methodology, code explanation, metrics, results, and LaTeX source is included in:

```
/report.pdf
```

---

## Future Enhancements

| Improvement                              | Benefit                  |
| ---------------------------------------- | ------------------------ |
| Use HMAC or TESLA for authenticated DIOs | Prevent forged packets   |
| Adaptive blacklisting timer              | Reduce false positives   |
| Support for mobile nodes                 | Extend beyond static RPL |

---

## Acknowledgements

* Guide: **CS366 - Internet of Things Faculty, NITK**

```
