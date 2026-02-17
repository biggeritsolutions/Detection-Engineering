# Practical Detection Engineering
Author: David Bigger  
Email: david@davidbigger.com  

## Philosophy

Detection engineering is not about alert volume — it's about adversary cost.

This repository contains practical Sigma rules and detection write-ups focused on:
- Small and mid-sized business (SMB) environments
- Windows-heavy ecosystems
- My personal experiences
- Minimal telemetry assumptions
- High-signal tradecraft detection
- Clear tuning guidance

The goal is simple:
Make intrusion expensive.
Reduce dwell time.
Detect attacker behavior — not just tools.

All detections are written with:
- Operational context
- False positive considerations
- Hunt expansion ideas
- Practical telemetry assumptions

## Structure

- `/sigma/` → Sigma detection rules
- `/detections/` → Deep-dive detection breakdowns
- MITRE ATT&CK mappings included where applicable

This is an evolving body of work focused on real-world attacker tradecraft observed in ransomware, intrusion sets, and hands-on-keyboard activity targeting SMB networks.