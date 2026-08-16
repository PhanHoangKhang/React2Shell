# Docker Lab & PoC Validation: React2Shell (CVE-2025-55182)

> **Disclaimer:** This repository and its PoC artifacts are created strictly for educational, research, and defensive security demonstration purposes within an isolated lab environment. Unsanctioned testing against external systems is strictly prohibited.

---

## 1. Project Governance & Authorization Boundary

### Project Purpose
This repository provides a reproducible, dual-container Docker environment designed to analyze, exploit, and validate mitigations for the React Server Components (RSC) Flight Protocol Deserialization vulnerability (popularly referenced as **React2Shell** / **CVE-2025-55182**). The lab demonstrates post-exploitation impact on an unpatched Next.js build and proves mitigation efficacy on a patched build.

### Target
- **In-Scope Targets:**
  - `http://127.0.0.1:3001` (`react2shell-vulnerable` container)
  - `http://127.0.0.1:3002` (`react2shell-patched` container)
- **Out-of-Scope:** Any external domain, public network interface, host machine operating system, or cloud infrastructure.

### Lab Safety Controls
- **Network Isolation:** All containers run within a private Docker bridge network with outbound internet routing disabled (`internal: true`).
- **Loopback Binding:** Exposed ports are strictly bound to `127.0.0.1` (localhost) to prevent external LAN accessibility.
- **Dummy Secrets:** Simulated credentials (`DUMMY_SECRET=LAB_VULNERABLE_SECRET_DO_NOT_USE_12345`) are utilized for exfiltration testing to eliminate sensitive data exposure.

## 2. Environment Setup & Operational Instructions

### Prerequisites
- **Docker Desktop** (Engine `24.0.0+`, Compose `v2.20.0+`)
- **Python** (`3.8+` — Standard library only for base automation)
- **cURL** (WSL, Linux, or PowerShell built-in)

### Installation
Clone the repository and verify your local environment:
```bash
git clone https://github.com/rmit-nct/React2Shell.git
```
### Lab Startup
Navigate to the lab/ directory and initialize both dual-build containers:
```bash
cd lab
docker-compose up -d --build
cd ..
```
### Vulnerability Detection
Run the detection scanner in both labs:
#### 1. Scan the patched lab 
```bash
python src/react2shell_scanner.py lab/patched
```
#### 2. Scan the vulnerable lab
```bash
python src/react2shell_scanner.py lab/vulnerable
```

### Dynamic Exploitation & Validation (PoC)
To execute the exploit validation tests and verify exfiltration artifacts, please refer to the detailed step-by-step PoC guide:

👉 **[View PoC & Vulnerability Validation Guide (`poc_reference.md`)](./lab/poc/poc_reference.md)**


