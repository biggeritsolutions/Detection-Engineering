# Homelab — Software Stack

---

## Pi-hole (DNS / Ad-blocking)

**Node:** Pi-hole | Raspbian Bookworm (32-bit)

| Component | Version |
|-----------|---------|
| Pi-hole Core | 6.x |
| FTL | 6.x |
| Web Interface | 6.x |

Network-wide DNS sinkhole and ad-blocker serving the entire homelab subnet.

---

## NAS (Network Attached Storage)

**Node:** NAS | Debian Trixie (64-bit)

| Software | Version |
|----------|---------|
| OpenMediaVault | 8.x (Synchrony) |

Centralised file storage for the cluster.

---

## Dock1 — General Services

**Node:** Dock1 | Debian Bookworm (64-bit) | Docker + Compose

| Service | Description |
|---------|-------------|
| Mealie | Self-hosted recipe manager |
| Nginx Proxy Manager | Reverse proxy + SSL termination |
| Uptime Kuma | Service uptime monitoring |

---

## Dock2 — Search

**Node:** Dock2 | Debian Bookworm (64-bit) | Docker + Compose

| Service | Description |
|---------|-------------|
| SearXNG | Privacy-respecting metasearch engine |

---

## Dock3 — General Docker Host

**Node:** Dock3 | Debian Trixie (64-bit) | Docker + Compose

*Available capacity — services TBD.*

---

## Dock4 — High-Performance Docker Host

**Node:** Dock4 (Orange Pi 5) | Ubuntu 22.04 LTS | Docker + Compose

*Available capacity — services TBD.*

---

## Ai-1 — Local LLM Inference

**Node:** Ai-1 | Ubuntu 24.04 LTS | Ollama

| Component | Detail |
|-----------|--------|
| Ollama | Latest stable |
| Models loaded | `qwen2.5-coder:7b` · `mxbai-embed-large` · `llama3.1:8b` · `phi3:mini` · `siem-llama-3.1` |

Dedicated to running local language models for coding assistance, embeddings, and SIEM-focused inference.

---

## Ai-2 — AI Frontend + Automation

**Node:** Ai-2 | Ubuntu 24.04 LTS | Docker + Compose

| Service | Description |
|---------|-------------|
| Open WebUI | Web frontend for Ollama models |
| Open Notebook | Notebook interface for LLM workflows |
| n8n | Low-code automation / workflow orchestration |
