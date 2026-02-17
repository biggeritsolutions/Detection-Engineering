# Homelab — Hardware Inventory

Dedicated subnet, all nodes on Gigabit Ethernet.

---

## Network

| Role | Device |
|------|--------|
| Gateway | Router (dedicated VLAN) |

---

## Raspberry Pi Cluster

All Pi nodes: **Raspberry Pi 4 Model B** — Quad-core Cortex-A72 @ 1.5GHz, 4GB RAM, 64GB SanDisk SD, Gigabit Ethernet @ 1000 Mbps.

| Node | Rev | OS |
|------|-----|----|
| Pi-hole | 1.2 | Raspbian Bookworm (32-bit) |
| NAS | 1.2 | Debian Trixie (64-bit) |
| Dock1 | 1.2 | Debian Bookworm (64-bit) |
| Dock2 | 1.1 | Debian Bookworm (64-bit) |
| Dock3 | 1.2 | Debian Trixie (64-bit) |
| Dock4 | — | See below |

---

## Dock4 — Orange Pi 5

| Spec | Detail |
|------|--------|
| CPU | Rockchip RK3588 — 4x Cortex-A76 @ 2.4GHz + 4x Cortex-A55 @ 1.8GHz (8 cores) |
| RAM | 16GB |
| Storage | 32GB SanDisk SD |
| Network | Gigabit Ethernet @ 1000 Mbps |
| OS | Ubuntu 22.04 LTS (Jammy Jellyfish) |

---

## AI Nodes — x86-64

| Node | CPU | RAM | Storage | OS |
|------|-----|-----|---------|-----|
| Ai-1 | Intel Core i5-9600K @ 3.70GHz (6 cores) | 16GB | 931GB Samsung SSD 860 | Ubuntu 24.04 LTS |
| Ai-2 | Intel Core i5-8400 @ 2.80GHz (6 cores) | 16GB | 119GB Kingston SSD | Ubuntu 24.04 LTS |
