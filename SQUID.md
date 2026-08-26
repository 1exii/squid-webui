# Squid Proxy Architecture & ACL Configuration Guide (`SQUID.md`)

> **System Component:** Squid Parental Control & Web Management System  
> **Deployment Target:** A NAS Docker host and a router with `iptables` policy routing
> **Installation Settings:** `deployments/local/` (see `deployments/README.md`)

---

## Deployment profile

Copy `deployments/example` to the Git-ignored `deployments/local` directory and
edit the network, device, certificate, and administrator settings there. All
management, deployment, and diagnostic entry points load that profile by
default; set `SQUID_DEPLOYMENT_DIR` to select a different installation. See
`deployments/README.md` for the complete workflow.

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
│ LAYER 2: SSL-Bump Domain Generator (configs/generate_bump_domains.py)                            │
│ • Runs on squid-proxy container startup, AND is mirrored by the Web UI on every                  │
│   policy compile so Web UI blocklist edits take effect without a restart.                        │
│ • Parses raw blocklists (/etc/squid/block-lists/*.txt) for entries with URL path rules (/).      │
│ • Deduplicates domains (.steamcommunity.com) to prevent Squid duplicate domain errors.           │
│ • Outputs: bump_domains.acl (the list) AND bump_domains.conf (the directives).                   │
│   When no path rule exists, bump_domains.conf is empty — no dead ACL is declared.                │
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
│ • Validates with `squid -k parse` via the Docker exec API BEFORE reloading, and                 │
│   rolls back to the previous ACLs if the generated config is rejected.                          │
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

   # Step 3: Bump global domains requiring deep URL path inspection.
   # The acl/ssl_bump pair lives in the generated bump_domains.conf, which is
   # empty when no blocklist defines a 'domain/path' rule.
   include /etc/squid/configs/bump_domains.conf

   # Step 4: Splice all other traffic by default (raw passthrough, zero CA needed on unrestricted devices)
   ssl_bump splice all
   ```
4. **Dynamic Policy Include** — placed AFTER the `Safe_ports` / `CONNECT` denies.
   Squid stops at the first matching `http_access` line, so a Web UI `allow` for a
   time window would otherwise short-circuit both port guards:
   ```acl
   http_access allow localhost
   http_access deny !Safe_ports
   http_access deny CONNECT !SSL_ports
   include /etc/squid/configs/rules.acl   # Web UI auto-generated device rules
   http_access allow localnet
   http_access deny all
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

# ── Device: Child Phone (192.0.2.50) ──
acl src_dev_192_0_2_50 src 192.0.2.50

acl list_gaming_txt dstdomain "/etc/squid/configs/domains_gaming.txt.acl"
acl sni_list_gaming_txt ssl::server_name "/etc/squid/configs/domains_gaming.txt.acl"
acl path_dom_gaming_txt_1 dstdomain .steamcommunity.com
acl sni_path_dom_gaming_txt_1 ssl::server_name .steamcommunity.com
acl path_url_gaming_txt_1 urlpath_regex -i ^/market

  # Always Block — Child Phone  (note the !CONNECT scoping)
  http_access deny !CONNECT src_dev_192_168_1_50 list_gaming_txt
  http_access deny src_dev_192_168_1_50 path_dom_gaming_txt_1 path_url_gaming_txt_1

  # Default Block with Unblock Windows — Child Phone
  acl time_allow_192_168_1_50_1 time MTWTF 16:00-20:00
  http_access allow src_dev_192_168_1_50 list_socialmedia_txt time_allow_192_168_1_50_1
  http_access deny !CONNECT src_dev_192_168_1_50 list_socialmedia_txt
```

#### Step C: Hot-Reload Signal (`reload_squid`)
When the admin clicks **Save & Apply** in the Web UI:
1. `POST /api/policies` saves policies and writes `/etc/squid/configs/rules.acl`.
2. `POST /api/apply` invokes `reload_squid()`.
3. `reload_squid()` first runs `squid -k parse` inside the container via the Docker
   exec API. If the generated configuration is rejected, the previous ACL files are
   restored and **no signal is sent** — Squid is the default route for HTTP/HTTPS on
   every intercepted host, so a reload that kills it takes those devices offline.
4. On a clean parse it sends `POST /containers/squid-proxy/kill?signal=HUP`.
5. Squid reloads `rules.acl` instantly without dropping active TCP connections.

---

## 3. Directory & File Reference

| File / Path | Type | Managed By | Description |
| :--- | :--- | :--- | :--- |
| `configs/squid.conf.template` | Static Config | Git / Manual | Master Squid configuration template. |
| `configs/generate_bump_domains.py` | Python Script | Git | Standalone SSL-bump domain generator script. |
| `configs/bump_domains.acl` | Auto-Generated ACL | Container start + Web UI | Domains requiring SSL Bumping for path rules. |
| `configs/bump_domains.conf` | Auto-Generated Config | Container start + Web UI | The `acl`/`ssl_bump` directives for the list above; empty when no path rule exists. |
| `configs/rules.acl` | Auto-Generated ACL | Web UI (`app.py`) | Contains active per-device conditional ACL rules. |
| `configs/ssl_bump.acl` | Auto-Generated ACL | Web UI (`app.py`) | Contains active per-device dynamic SSL Bump interception rules. |
| `configs/domains_*.acl` | Auto-Generated ACL | Web UI (`app.py`) | Deduplicated clean domain lists per blocklist category. |
| `block-lists/*.txt` | Raw Text Files | Administrator | Category domain and URL path blocklists. |
| `webui/app.py` | Python Application | Git | Flask Web UI backend API and ACL compiler. |

---

## 4. Troubleshooting & Operational Commands

### 1. Re-generate `bump_domains.acl` / `bump_domains.conf` manually
```bash
python3 configs/generate_bump_domains.py block-lists configs/bump_domains.acl
```
(The Web UI does this automatically on every **Save & Apply**.)

### 2. Verify Squid syntax inside proxy container
```bash
./squid-mgmt.sh dump-config
```

### 3. Trigger manual Squid SIGHUP reload
Use **Save & Apply** in the Web UI; it validates the generated configuration
before sending SIGHUP and rolls back invalid ACL output.

### 4. Inspect active rules inside container
```bash
SQUID_DIR=$PWD
source lib/load-deployment.sh
ssh "$QNAP_SERVER" "$QNAP_DOCKER exec $SQUID_CONTAINER_NAME cat /etc/squid/configs/rules.acl"
```

### 5. View Squid real-time access logs
```bash
./squid-mgmt.sh catlogs
```

---

## 5. Router Rules (`router/squid-proxy-rules.sh`)

`router/squid-proxy-rules.sh` is the **single source of truth** for the router-side
rules. `squid-mgmt.sh router-deploy` copies it, substitutes the profile's router
and proxy values, appends one `add_host` line per entry in the profile's
`proxy-hosts.conf`, syntax-checks the result,
and uploads it to `/jffs/scripts/squid-proxy-rules.sh`.

It uses **profile-configured fwmark policy routing, not DNAT.** This matters:
a DNAT + MASQUERADE scheme rewrites the source address to the router's, so every
request reaches Squid from the router address and all per-device `src` ACLs collapse to
a single client — filtering appears to work while applying the wrong policy to
everyone. Preserving the client IP is what makes `acl src_dev_<ip> src <ip>` mean
anything.

Every controlled client gets a catch-all UDP/443 `REJECT`, preventing arbitrary
HTTP/3 traffic from bypassing Squid. By default, a preceding Google/YouTube UDP
exception preserves YouTube QUIC performance. Add the optional `no_quic` flag to
a client in the deployment profile's `proxy-hosts.conf` to omit that exception and force YouTube to
fall back to TCP 443 through Squid, allowing category enforcement and the custom
HTTPS block page. During an allowed schedule, Squid splices that TCP connection
so YouTube retains native end-to-end TLS.

```text
192.0.2.20  windows-client  no_quic
192.0.2.21  laptop-client  no_quic no_vpn
192.0.2.22  ubuntu-client
```

The independent `no_vpn` flag blocks Cloudflare WARP's documented consumer,
WireGuard, MASQUE, FedRAMP, and client-orchestration ingress addresses, plus the
consumer endpoint observed on this network. The router removes any matching
established conntrack flows during deployment so hardware acceleration cannot
keep an old WARP tunnel alive. This is deliberately WARP-specific: arbitrary
VPNs using general HTTPS endpoints cannot be distinguished safely from normal
web traffic by port alone.

---

## 6. Why deny rules are scoped to `!CONNECT`

For an intercepted TLS connection Squid peeks the ClientHello, synthesises a
`CONNECT host:443` request, and runs `http_access` on it **before** consulting
`ssl_bump`. A plain `http_access deny <src> <list>` therefore matches at the
CONNECT stage: Squid writes the `ERR_ACCESS_DENIED` HTML in cleartext onto a
socket where the browser is still waiting for a TLS ServerHello, the browser
discards it as a protocol error, and the `ssl_bump bump` rule never runs at all.

The symptom is a site that is blocked but shows a browser TLS error instead of the
parental block page, with an access log line like:

```
TCP_DENIED/403 8631 CONNECT www.pornhub.com:443 - HIER_NONE/- text/html
```

The 8631 bytes are the block page — delivered where it cannot be rendered. The
same block over plain HTTP works, because there is no CONNECT stage:

```
TCP_DENIED/403 8636 GET http://www.youtube.com/ - HIER_NONE/- text/html
```

Scoping the deny to `!CONNECT` lets the tunnel be established and bumped; the
decrypted inner `GET` then matches the same deny and the block page is delivered
*inside* the TLS session. A correctly bumped block logs as:

```
TCP_DENIED/403 ... GET https://www.pornhub.com/ ...
```

### The invariant this creates

`!CONNECT` scoping is only safe when the connection is **guaranteed** to be
bumped. Otherwise the CONNECT falls through to `http_access allow localnet` and
the site becomes fully reachable. Two things enforce this:

1. `compile_device_policies_acls()` emits the `!CONNECT` form only for
   `ssl_bump_mode` of `blocked_only` or `all` — exactly the modes for which
   `ssl_bump.acl` emits a matching bump rule. Selective rules use dedicated
   `ssl::server_name` ACLs (`sni_list_*` / `sni_path_dom_*`), because a
   transparently intercepted CONNECT initially identifies the original
   destination IP; reusing `dstdomain` here works for explicit proxying but
   silently splices blocked traffic on port 3130. Any other mode keeps the
   CONNECT-level deny (blocked, but with a TLS error rather than a page).
   For scheduled categories, matching `ssl_bump splice ... time_allow_*` rules
   precede the fallback bump. Allowed windows therefore use native end-to-end
   TLS (required by media transports such as YouTube UMP), while the same domain
   is bumped and denied outside its allow window.
2. `http_port 3128` carries the `ssl-bump` flag. Any port that handles CONNECT
   must be able to bump, or a client manually configured to use it would tunnel
   straight past the blocklists.

Browsers should use the profile-derived Web UI `/proxy.pac` endpoint.
The PAC file keeps private LAN destinations direct and sends Internet requests
through explicit port 3128. Router interception remains a safety net for clients
that ignore proxy settings, but it is not reliable for CDN-heavy applications:
Squid must reject an intercepted CONNECT when its independent DNS lookup does not
contain the packet's original destination IP, even when both CDN addresses are
valid.

**TC-3.4d/e** in the test suite cross-reference both generated files and fail if
any `!CONNECT` deny lacks a correctly typed SNI bump rule.

### Client CA trust is still required

Once bumping works, the browser must trust `squid-ca.crt` or it shows a
certificate warning instead of the block page — and for HSTS sites (most large
ones) that warning cannot be clicked through. Install the CA with
`squid-mgmt.sh linux-deploy`, or from the Web UI's `/download/cert.crt` endpoint.
