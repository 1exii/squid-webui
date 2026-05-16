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
3. **ACL Rule & SSL Bump Generation:** Active `/etc/squid/configs/rules.acl`, `/etc/squid/configs/ssl_bump.acl`, and `/etc/squid/configs/bump_domains.acl` contents.
4. **Squid Syntax Parsing:** Validates `squid -k parse` inside the container to ensure 100% clean configuration parsing.
5. **Traffic Interception & Selective SSL Bumping:** Spotify port 4070 redirection, unblocked HTTPS TLS splicing, blocked domain HTTPS bumping & custom error page rendering, URL path selective deep inspection (`steamcommunity.com/market` blocked vs `steamcommunity.com` permitted), and YouTube QUIC/UDP firewall blocking.

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
| **TC-2.6: Ubuntu Installer** | Verifies automated Ubuntu Linux onboarding shell script. | `GET /download/install-ubuntu.sh` | Returns HTTP status `200 OK` with bash script content. |
| **TC-2.7: Policy Apply Pipeline** | Tests hot-reload trigger via Docker Socket API. | `POST /api/apply` | JSON response containing `"success": true` and reloading Squid via SIGHUP (`kill -HUP`). |

---

### Suite 3: Configuration & ACL Integrity

| Test Case | Description | Verification Logic | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-3.1: Squid Syntax Validation** | Verifies configuration syntax inside `squid-proxy`. | Exec `squid -k parse` inside container. | Parsing succeeds with no FATAL/ERROR lines. |
| **TC-3.2: Active `rules.acl` Inspection** | Inspects `/etc/squid/configs/rules.acl` inside `squid-proxy`. | Exec `cat /etc/squid/configs/rules.acl` inside container. | Contains auto-generated per-device `src` ACLs, `dstdomain` ACLs, and conditional `http_access` rules. |
| **TC-3.3: Active `ssl_bump.acl` Inspection** | Inspects `/etc/squid/configs/ssl_bump.acl` inside `squid-proxy`. | Exec `cat /etc/squid/configs/ssl_bump.acl` inside container. | Contains dynamic per-device `ssl_bump bump <src_acl> <list_acl>` rules. |
| **TC-3.4: Active `bump_domains.acl` Inspection** | Inspects `/etc/squid/configs/bump_domains.acl` generated during container boot. | Exec `cat /etc/squid/configs/bump_domains.acl` inside container. | Contains clean deduplicated domain list for path-based rules (e.g., `.opera.com`, `.roblox.com`, `.steamcommunity.com`). |
| **TC-3.5: Local CA Certs Integrity** | Checks local `squid-ca.pem` and `squid-ca.crt` exist. | File existence check in `certs/`. | Both CA files exist locally. |

---

### Suite 4: Network Interception & Selective SSL Bumping

| Test Case | Description | Execution Command | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-4.1: Allowed HTTP Traffic** | Verifies unblocked domain HTTP request. | `curl http://example.com` (via proxy) | Returns HTTP `200 OK` with real remote content. |
| **TC-4.2: Unblocked HTTPS TLS Splicing** | Verifies unblocked domain HTTPS connection is spliced (raw TLS passthrough). | `curl https://example.com` (via proxy) | Returns HTTP `200 OK` without SSL certificate warnings. |
| **TC-4.3: Blocked Domain HTTPS Bumping** | Verifies blocked HTTPS domain is bumped and serves Parental Block Page. | `curl https://pornhub.com` (via proxy) | Intercepted via SSL bump, returning HTTP 403 or custom Parental Block page. |
| **TC-4.4: URL Path Selective Inspection** | Verifies deep URL path inspection: `/market` path blocked while base domain allowed. | `curl https://steamcommunity.com/market`<br>`curl https://steamcommunity.com` | `/market` URL path blocked; base domain permitted. |
| **TC-4.5: Strict SSL Trust Verification** | Verifies Root CA certificate trust without `-k`. | `curl https://example.com` (without `-k`) | Passes clean TLS handshake if CA is installed in client trust store. |
| **TC-4.6: Spotify Port 4070 Redirection** | Verifies TCP 4070 redirection and interception rules. | Check router mangle table & container NAT REDIRECT for port 4070. | Both router and container rules present and active. |
| **TC-4.7: YouTube QUIC Router Firewall Block** | Verifies router iptables rules drop UDP 443 (QUIC) to force YouTube to fallback to TCP HTTPS. | Exec `iptables -L FORWARD -n -v` on router. | Router FORWARD rules present. |
| **TC-4.8: Dynamic Video Block & Unblock Lifecycle** | Tests dynamic Web UI policy changes for video category (Unblock -> Block -> Unblock). | `POST /api/policies` -> test `https://youtube.com` | Unblocked state returns HTTP 200; Blocked state returns HTTP 403 / SSL bump block; Restores original state cleanly. |
| **TC-4.9: Custom Block Page Content Verification** | Validates HTML error page payload for blocked categories. | Query blocked domain via proxy | Response contains HTTP 403, `X-Squid-Error: ERR_ACCESS_DENIED`, `<title>Webpage Blocked`, and parental warning message. |

---

## 4. How to Run the Test Suite

Run the test suite directly from the command line:

```bash
# Default run (targets remote client 192.168.8.30 via SSH, fails if unreachable)
./debug/debug-proxy.sh

# Run using local host IP as the client target (direct proxy execution)
./debug/debug-proxy.sh --local

# Run targeting a specific custom client IP
./debug/debug-proxy.sh --client-ip 192.168.1.11

# Run with container redeployment before running tests
./debug/debug-proxy.sh --redeploy
./debug/debug-proxy.sh --local --redeploy
```

---

## 5. Test Suite Output Format

The test runner outputs color-coded result summaries:
- `[PASS]` (Green): Test assertion succeeded.
- `[FAIL]` (Red): Assertion failed; prints failure reason and log snippet.
- `[WARN]` (Yellow): Diagnostic warning or non-critical notice.
- `[INFO]` (Cyan): Execution progress and container status.
