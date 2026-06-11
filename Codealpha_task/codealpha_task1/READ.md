# Task 1 — Network Intrusion Detection System

## Overview
A Python-based network packet sniffer and intrusion detection system that captures and analyzes live network traffic to detect suspicious activity and potential intrusion attempts.

## Features
- Captures live network packets in real time
- Analyzes packet headers (IP, TCP, UDP, ICMP)
- Detects suspicious traffic patterns and potential intrusions
- Logs all captured packets and alerts to `packets.log`
- Displays source/destination IP addresses and ports

## How to Run

**Install dependencies first:**
```bash
pip install scapy
```

**Run the sniffer (requires admin/root):**
```bash
# Windows (run as Administrator)
python sniffer.py

# Linux/Mac
sudo python sniffer.py
```

**Note:** Requires [Npcap](https://npcap.com/) installed on Windows for packet capture.

## Files
| File | Description |
|---|---|
| `sniffer.py` | Main packet sniffer and IDS script |
| `packets.log` | Log file of captured packets and alerts |

## Tools & Libraries
- **Python 3.x**
- **Scapy** — packet capture and analysis
- **Npcap** — Windows packet capture driver
- **Socket** — network interface handling
