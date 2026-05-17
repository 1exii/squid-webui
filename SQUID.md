# Squid Proxy Architecture & ACL Configuration Guide (`SQUID.md`)

> **System Component:** Squid Parental Control & Web Management System  
> **Deployment Target:** QNAP NAS Container Station (`admin@192.168.1.2`, containers `squid-proxy` and `squid-webui`)  
> **Router Daemon:** ASUS Router (`admin@192.168.0.1`, `nftables` / `iptables` Policy Routing & Port Redirection)

---

## 1. Overview & Architectural Principles

The Squid Proxy system provides transparent HTTP/HTTPS access control, time-window parental controls, and selective SSL bumping across all network devices. 

The architecture is divided into **3 distinct configuration layers**:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: Static Core Configuration (squid.conf.template)                                         │
│ • Proxy ports (3128 explicit, 3129 HTTP intercept, 3130 HTTPS ssl-bump intercept)                 │
│ • Core safety ACLs (SSL_ports, Safe_ports, localnet)                                            │
│ • Static SSL Bumping workflow (peek step1 -> per-device ssl_bump.acl -> bump_domains -> splice)   │
│ • Master includes: include /etc/squid/configs/rules.acl & ssl_bump.acl                            │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
                                                │
                                                ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 2: Container Startup SSL-Bump Generator (configs/generate_bump_domains.py)                 │
│ • Runs automatically on squid-proxy container startup / deployment.                               │
│ • Parses raw blocklists (/etc/squid/block-lists/*.txt) for entries with URL path rules (/).      │
│ • Deduplicates domains (.steamcommunity.com) to prevent Squid duplicate domain errors.           │
│ • Outputs: /etc/squid/configs/bump_domains.acl                                                   │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
                                                │
                                                ▼
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 3: Dynamic Web UI Device Policy Engine (webui/app.py)                                       │
│ • Parses raw blocklists into clean per-blocklist ACL files (/etc/squid/configs/domains_<bl>.acl).│
│ • Compiles per-device 30-min schedule matrices & blocklist selections.                           │
│ • Outputs per-device src ACLs, dstdomain ACLs, time ACLs, and http_access rules.                │
│ • Generates per-device SSL bump rules so blocked sites render Parental Block Pages over HTTPS.   │
│ • Outputs: /etc/squid/configs/rules.acl & /etc/squid/configs/ssl_bump.acl                         │
│ • Triggers live reload via Docker Daemon Unix socket SIGHUP (/var/run/docker.sock).             │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Configuration Breakdown

### 2.1 Static Squid Configuration (`configs/squid.conf.template`)

`squid.conf.template` contains core proxy settings that remain constant across Web UI policy changes:

1. **Proxy Port Definitions**:
   - `http_port 3128`: Explicit HTTP proxy port for manual device configuration.
   - `http_port 3129 intercept`: Transparent HTTP interception port (DNAT redirected from router port 80).
   - `https_port 3130 intercept ssl-bump`: Transparent HTTPS interception port with SSL Bumping (DNAT redirected from router port 443).
2. **Error Pages Directory**:
   - `error_directory /etc/squid/configs/errors`: Renders customized parental block page (`ERR_ACCESS_DENIED`) when access is denied.
3. **SSL Bumping Workflow**:
   ```acl
   # Step 1: Peek at client TLS ClientHello to extract SNI
   acl step1 at_step SslBump1
   ssl_bump peek step1

   # Step 2: Dynamic Per-Device SSL Bumping (configured via /etc/squid/configs/ssl_bump.acl)
   # Bumps blocked categories specifically for target devices so custom block pages render
   include /etc/squid/configs/ssl_bump.acl

   # Step 3: Bump global domains requiring deep URL path inspection
   acl bump_domains dstdomain "/etc/squid/configs/bump_domains.acl"
   ssl_bump bump bump_domains

   # Step 4: Splice all other traffic by default (raw passthrough, zero CA needed on unrestricted devices)
   ssl_bump splice all
   ```
4. **Dynamic Policy Include**:
   ```acl
   # Include Web UI auto-generated device rules
   include /etc/squid/configs/rules.acl
   ```

---

### 2.2 Container Startup SSL-Bump Generator (`configs/generate_bump_domains.py`)

Selective SSL Bumping requires decrypting HTTPS traffic ONLY for domains that have deep URL path rules (e.g. `steamcommunity.com/market` or `opera.com/developer/extensions`).

- **Script:** `configs/generate_bump_domains.py`
- **Execution Hook:** `docker/docker-entrypoint.sh` runs the script during container boot:
  ```sh
  if [ -f "/etc/squid/configs/generate_bump_domains.py" ]; then
      python3 /etc/squid/configs/generate_bump_domains.py /etc/squid/block-lists /etc/squid/configs/bump_domains.acl
  fi
  ```
- **Output File:** `/etc/squid/configs/bump_domains.acl`
- **Example Output**:
  ```acl
  # Auto-generated: Domains requiring SSL Bumping for deep URL path rules
  .opera.com
  .roblox.com
  .steamcommunity.com
  ```

---

### 2.3 Web UI Dynamic Policy Engine (`webui/app.py` & `rules.acl`)

The Web UI compiles user device policies into `/etc/squid/configs/rules.acl`.

#### Step A: Domain Deduplication & Clean ACL File Generation (`parse_blocklists`)
When Web UI compiles rules, `parse_blocklists()` reads each `.txt` blocklist file from `/etc/squid/block-lists/`:
- **Domain Deduplication (`deduplicate_domains`)**:
  Squid `dstdomain` matching rules state that `.domain.com` matches `domain.com` and all subdomains (`*.domain.com`). Having both `.domain.com` and `domain.com` in an ACL causes Squid duplicate domain errors/crashes.
  `deduplicate_domains()` subsumes exact domains and subdomains into wildcard bases.
- **Output Files**: `/etc/squid/configs/domains_<blocklist>.acl` (e.g., `domains_gaming.txt.acl`).

#### Step B: Device Policy ACL Compilation (`compile_device_policies_acls`)
`compile_device_policies_acls()` parses `device_policies.json` and outputs `/etc/squid/configs/rules.acl`:

```acl
# ===========================================================
# AUTO-GENERATED BY SQUID WEB UI - DEVICE POLICIES
# ===========================================================

# ── Device: Child Phone (192.168.1.50) ──
acl src_dev_192_168_1_50 src 192.168.1.50

acl list_gaming_txt dstdomain "/etc/squid/configs/domains_gaming.txt.acl"
acl path_dom_gaming_txt_1 dstdomain .steamcommunity.com
acl path_url_gaming_txt_1 urlpath_regex -i ^/market

  # Always Block — Child Phone
  http_access deny src_dev_192_168_1_50 list_gaming_txt
  http_access deny src_dev_192_168_1_50 path_dom_gaming_txt_1 path_url_gaming_txt_1

  # Default Block with Unblock Windows — Child Phone
  acl time_allow_192_168_1_50_1 time MTWTF 16:00-20:00
  http_access allow src_dev_192_168_1_50 list_socialmedia_txt time_allow_192_168_1_50_1
  http_access deny src_dev_192_168_1_50 list_socialmedia_txt
```

#### Step C: Hot-Reload Signal (`reload_squid`)
When the admin clicks **Save & Apply** in the Web UI:
1. `POST /api/policies` saves policies and writes `/etc/squid/configs/rules.acl`.
2. `POST /api/apply` invokes `reload_squid()`.
3. `reload_squid()` communicates with the Docker daemon via Unix Socket `/var/run/docker.sock`:
   `POST /containers/squid-proxy/kill?signal=HUP`
4. Squid reloads `rules.acl` instantly without dropping active TCP connections.

---

## 3. Directory & File Reference

| File / Path | Type | Managed By | Description |
| :--- | :--- | :--- | :--- |
| `configs/squid.conf.template` | Static Config | Git / Manual | Master Squid configuration template. |
| `configs/generate_bump_domains.py` | Python Script | Git | Standalone SSL-bump domain generator script. |
| `configs/bump_domains.acl` | Auto-Generated ACL | Container Startup | Contains domains requiring SSL Bumping for path rules. |
| `configs/rules.acl` | Auto-Generated ACL | Web UI (`app.py`) | Contains active per-device conditional ACL rules. |
| `configs/ssl_bump.acl` | Auto-Generated ACL | Web UI (`app.py`) | Contains active per-device dynamic SSL Bump interception rules. |
| `configs/domains_*.acl` | Auto-Generated ACL | Web UI (`app.py`) | Deduplicated clean domain lists per blocklist category. |
| `block-lists/*.txt` | Raw Text Files | Administrator | Category domain and URL path blocklists. |
| `webui/app.py` | Python Application | Git | Flask Web UI backend API and ACL compiler. |

---

## 4. Troubleshooting & Operational Commands

### 1. Re-generate `bump_domains.acl` manually
```bash
python3 configs/generate_bump_domains.py block-lists configs/bump_domains.acl
```

### 2. Verify Squid syntax inside proxy container
```bash
ssh admin@192.168.1.2 "/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker exec squid-proxy squid -k parse"
```

### 3. Trigger manual Squid SIGHUP reload
```bash
ssh admin@192.168.1.2 "/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker kill -s HUP squid-proxy"
```

### 4. Inspect active rules inside container
```bash
ssh admin@192.168.1.2 "/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker exec squid-proxy cat /etc/squid/configs/rules.acl"
```

### 5. View Squid real-time access logs
```bash
ssh admin@192.168.1.2 "/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker exec squid-proxy tail -f /var/log/squid/access.log"
```
