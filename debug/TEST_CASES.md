# Squid Proxy & Web UI Integration Test Suite (`TEST_CASES.md`)

> **Target Script:** `debug/debug-proxy.sh`  
> **Environment:** QNAP NAS Container Station (`squid-proxy` and `squid-webui` Docker containers)  
> **Execution Location:** Dev machine / host runner (`/home/admin/GitHub/personal/home-network/squid`)

---

## 1. Overview & Objectives

The test runner `debug/debug-proxy.sh` provides automated end-to-end (E2E) verification for the Squid Parental Control Proxy system and Web UI management daemon. 

It validates:
1. **Container & System Health:** Docker container state (`squid-proxy` and `squid-webui`) and network binding.
2. **Web UI REST API Endpoints:** Public and admin endpoint responses, JSON schema integrity, Root CA certificate downloads, client installer generation, policy save pipeline (`POST /api/policies`), and SIGHUP hot-reload execution (`POST /api/apply`).
3. **ACL Rule Generation:** Active `/etc/squid/configs/rules.acl` and `/etc/squid/configs/bump_domains.acl` contents.
4. **Traffic Interception & Selective SSL Bumping:** Spotify port 4070 redirection, unblocked HTTPS TLS splicing, blocked plain domain SNI denial, URL path selective deep inspection (`steamcommunity.com/market` blocked vs `steamcommunity.com` permitted), and YouTube QUIC/UDP firewall blocking.

---

## 2. Test Environment & Prerequisites

- **Target QNAP Host:** `192.168.1.2` (SSH user: `admin`)
- **Container Network:** `192.168.1.90` (`squid-proxy`), `192.168.1.91` (`squid-webui`)
- **Docker Binary:** `/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker`
- **Proxy Ports:**
  - `3128`: Explicit HTTP proxy
  - `3129`: Transparent HTTP interception
  - `3130`: Transparent HTTPS SSL-bump interception
  - `3131`: Web UI Management API

---

## 3. Test Cases Specification

### Suite 1: Container & Health Diagnostics

| Test Case | Description | Verification Logic | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-1.1: Container Status** | Verifies `squid-proxy` and `squid-webui` Docker containers are running on QNAP. | Runs `docker ps` over SSH and checks for container names. | Both containers reported `UP` and running. |
| **TC-1.2: Web UI Reachability** | Verifies HTTP port 3131 responsiveness on Web UI container IP / QNAP IP. | `curl -m 2 http://${WEBUI_IP}:3131/api/auth/status` | Returns HTTP status 200 OK. |

---

### Suite 2: Web UI REST API Integration

| Test Case | Description | Endpoint & Payload | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-2.1: Auth Status** | Checks authentication API. | `GET /api/auth/status` | JSON response containing `"authenticated"` status. |
| **TC-2.2: Device List** | Checks device inventory API. | `GET /api/devices` | JSON array containing devices parsed from `devices.list`. |
| **TC-2.3: Policy Retrieval** | Checks device policy API. | `GET /api/policies` | JSON object containing device schedule matrices. |
| **TC-2.4: Blocklists List** | Checks blocklist directory listing. | `GET /api/blocklists` | JSON array listing available `.txt` blocklist category files. |
| **TC-2.5: CA Downloads** | Verifies Root CA certificate download endpoints. | `GET /download/cert.crt`<br>`GET /download/cert.pem` | Both endpoints return HTTP status `200 OK`. |
| **TC-2.6: Policy Save Pipeline** | Tests policy save API and rule compilation. | `POST /api/policies`<br>`Body: {"policies": {...}}` | JSON response containing `"success": true`. |
| **TC-2.7: Policy Apply Pipeline** | Tests hot-reload trigger via Docker Socket API. | `POST /api/apply` | JSON response containing `"success": true` and reloading Squid via SIGHUP (`kill -HUP`). |

---

### Suite 3: Configuration & ACL Integrity

| Test Case | Description | Verification Logic | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-3.1: Active `rules.acl` Inspection** | Inspects `/etc/squid/configs/rules.acl` inside `squid-proxy`. | Exec `cat /etc/squid/configs/rules.acl` inside container. | Contains auto-generated per-device `src` ACLs, `dstdomain` ACLs, and conditional `http_access` rules. |
| **TC-3.2: Active `bump_domains.acl` Inspection** | Inspects `/etc/squid/configs/bump_domains.acl` generated during container boot. | Exec `cat /etc/squid/configs/bump_domains.acl` inside container. | Contains clean deduplicated domain list for path-based rules (e.g., `.opera.com`, `.roblox.com`, `.steamcommunity.com`). |

---

### Suite 4: Network Interception & Selective SSL Bumping

| Test Case | Description | Execution Command | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-4.1: Spotify Port 4070 Redirection** | Verifies TCP 4070 redirection and interception rules. | `curl -m 3 --proxy http://192.168.1.90:3128 http://ap.spotify.com:4070` | Connection handled cleanly by proxy without connection refusal. |
| **TC-4.2: Unblocked HTTPS TLS Splicing** | Verifies unblocked domain HTTPS connection is spliced (raw TLS passthrough). | `curl -m 5 -s -o /dev/null -w "%{http_code}" --proxy http://192.168.1.90:3128 https://www.wikipedia.org` | Returns HTTP `200 OK` without SSL certificate errors. |
| **TC-4.3: Plain Blocked Domain Denial** | Verifies plain blocked domain SNI denial. | `curl -m 5 -s --proxy http://192.168.1.90:3128 https://pornhub.com` | Connection refused or denied at SNI level. |
| **TC-4.4: URL Path Selective Inspection** | Verifies deep URL path inspection: `/market` path blocked while base domain allowed. | `curl -m 5 --proxy http://192.168.1.90:3128 https://steamcommunity.com/market` (Blocked)<br>`curl -m 5 --proxy http://192.168.1.90:3128 https://steamcommunity.com` (Allowed) | `/market` URL path blocked; base domain permitted. |
| **TC-4.5: YouTube QUIC Router Firewall Block** | Verifies router iptables rules drop UDP 443 (QUIC) to force YouTube to fallback to TCP HTTPS. | Exec `iptables -L FORWARD -n -v` on router or test UDP 443 packet drop. | UDP port 443 packets dropped, forcing HTTP/2 over TCP. |

---

## 4. How to Run the Test Suite

Run the test suite directly from the command line:

```bash
# Basic run (skips container redeployment)
./debug/debug-proxy.sh

# Run with full container redeployment before running tests
REBUILD=1 ./debug/debug-proxy.sh
```

---

## 5. Test Suite Output Format

The test runner outputs color-coded result summaries:
- `[PASS]` (Green): Test assertion succeeded.
- `[FAIL]` (Red): Assertion failed; prints failure reason and log snippet.
- `[INFO]` (Cyan): Execution progress and container status.
