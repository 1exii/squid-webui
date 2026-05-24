# Squid Proxy & Web UI Integration Test Suite (`TEST_CASES.md`)

> **Target Script:** `debug/debug-proxy.sh`
> **Environment:** QNAP NAS Container Station (`squid-proxy` and `squid-webui` Docker containers)
> **Execution Location:** Dev machine / host runner (`/home/admin/GitHub/personal/home-network/squid`)

---

## 1. Overview & Objectives

`debug/debug-proxy.sh` provides automated end-to-end verification for the Squid parental-control proxy and its Web UI management daemon.

It validates:

1. **Router & container infrastructure** — fwmark policy routing (`0x5000` → table 150 → Squid), the mangle `SQUID_MARK` chain, container state, container NAT `REDIRECT` rules, and Squid's listening ports.
2. **Web UI REST API** — endpoint contracts, CA certificate downloads, client installer, the policy save/apply pipeline, and the **authentication posture** of the write endpoints.
3. **Configuration & ACL integrity** — `squid -k parse`, empty-ACL detection, `rules.acl` / `ssl_bump.acl` / `bump_domains.acl` contents, and cross-file ACL reference consistency.
4. **Traffic interception & selective SSL bumping** — spliced pass-through, bumped block pages, deep URL path rules, and CA trust.
5. **Management CLI** — `squid-mgmt.sh dump-config` and `catlogs`.
6. **Router advanced rules** — Spotify TCP 4070 and QUIC handling (YouTube allow-list **and** the global UDP/443 reject that prevents proxy bypass).

**Exit code:** `0` when no assertion failed, `1` otherwise — the suite is safe to wire into CI or a cron check.

---

## 2. Test Environment & Prerequisites

- **Target QNAP Host:** `192.168.1.2` (SSH user: `admin`)
- **Container Network:** `192.168.1.90` (`squid-proxy`), `192.168.1.91` (`squid-webui`)
- **Docker Binary:** `/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker`
- **Proxy Ports:**
  - `3128`: Explicit HTTP proxy (**no `ssl-bump` flag** — see §6)
  - `3129`: Transparent HTTP interception
  - `3130`: Transparent HTTPS SSL-bump interception
  - `3131`: Web UI Management API (on the container IP only — the webui runs on a
    macvlan network, so `-p 3131:3131` does **not** publish it on the QNAP host IP)
- **Test client:** must be listed in `router/proxy-hosts.conf` for its traffic to be
  intercepted, and must be reachable over SSH from the runner.

---

## 3. Test Cases Specification

### Suite 1: Infrastructure & Routing

| Test Case | Description | Verification Logic | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-1.1a: Policy Rule** | Router `ip rule` routes marked packets to table 150. | `ip rule show` on the router. | Rule `fwmark 0x5000/0x5000 lookup 150` present. |
| **TC-1.1b: Table 150 Route** | Table 150 forwards to the Squid container. | `ip route show table 150`. | `default via 192.168.1.90`. |
| **TC-1.2a: Mangle Chain** | `SQUID_MARK` chain exists. | `iptables -t mangle -L SQUID_MARK -n -v`. | Chain present. |
| **TC-1.2b: Per-Host Marking** | Every host in `proxy-hosts.conf` is marked. | Cross-reference `proxy-hosts.conf` against the chain. | A MARK rule per configured host. |
| **TC-1.3a/b: Container Status** | `squid-proxy` and `squid-webui` are running. | `docker ps --format '{{.Names}}\t{{.Status}}'`; status must start with `Up`. | Both `Up`. On failure the last 25 lines of `docker logs squid-proxy` are printed. |
| **TC-1.4: Container NAT** | Container `REDIRECT` rules preserve `SO_ORIGINAL_DST`. | `iptables-legacy -t nat -L PREROUTING -n -v` inside the container. | `80→3129`, `443→3130`, `4070→3130` all present. |
| **TC-1.5: Listening Ports** | Squid is actually accepting connections. | `netstat -tlnp` inside the container. | Listening on `3128`, `3129`, `3130`. |

> **Container-down guard.** Every container assertion runs through a helper that
> detects `is not running` / `No such container` / daemon errors and reports a
> FAIL. Before this guard, a stopped `squid-proxy` still produced `[PASS]` on the
> syntax and CLI checks, because the assertions grepped for the *absence* of the
> word `FATAL` in what was actually a Docker error message.

---

### Suite 2: Web UI REST API & Auth Posture

| Test Case | Description | Endpoint & Payload | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-2.0: Reachability & Dashboard** | Web UI answers on the container IP. | `GET /` and `GET /api/auth/status` | HTTP 200 with an HTML document. |
| **TC-2.1: Auth Status** | Authentication API contract. | `GET /api/auth/status` | JSON containing `"authenticated"`. |
| **TC-2.2: Device List** | Device inventory from `devices.list`. | `GET /api/devices` | JSON containing `"devices"`. |
| **TC-2.3: Policy Retrieval** | Device policy store. | `GET /api/policies` | JSON containing `"policies"`. |
| **TC-2.4: Blocklists List** | Blocklist directory listing. | `GET /api/blocklists` | JSON array of `.txt` category files. |
| **TC-2.5: CA Downloads** | Root CA download endpoints. | `GET /download/cert.crt`<br>`GET /download/cert.pem` | Both 200 **and** the payload parses as X.509 (DER and PEM respectively). A 200 carrying a JSON error body is a FAIL. |
| **TC-2.6a: PAC Endpoint** | Browser auto-configuration uses the explicit proxy without failing open. | `GET /proxy.pac` | PAC MIME type; Internet return is `PROXY 192.168.1.90:3128`; private LAN is `DIRECT`; no `PROXY …; DIRECT` fallback. |
| **TC-2.6b: Ubuntu Installer** | Linux client onboarding configures CA trust and PAC. | `GET /download/install-ubuntu.sh` | Bash script calls `update-ca-certificates`, installs managed Chrome PAC policy, and points at the WebUI PAC URL. |
| **TC-2.6c: Windows Installer** | Windows client onboarding configures CA trust and PAC. | `GET /download/install-windows.ps1` | Elevated PowerShell script imports the CA and sets the current user's `AutoConfigURL`. |
| **TC-2.7: Unauthenticated Write** | **Security regression check.** Policy writes must require a session. | `POST /api/policies` with no cookie | HTTP 401/403. A 200 is a FAIL — it means `is_authenticated()` in `webui/app.py` is still stubbed to `return True`, leaving every filtered device able to rewrite its own parental controls. |
| **TC-2.8a: Apply Pipeline** | Hot reload via the Docker socket. | `POST /api/apply` | JSON `"success": true`. |
| **TC-2.8b: Survives Reload** | Squid must not die on SIGHUP. | Re-check `docker ps` 3s after apply. | `squid-proxy` still `Up`. A dead proxy means the intercepted hosts lose all web access, because the router policy-routes 80/443/4070 at it. |

---

### Suite 3: Configuration & ACL Integrity

| Test Case | Description | Verification Logic | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-3.1: Syntax Validation** | `squid -k parse` inside the container. | Exit code **and** output are both checked. | Exit 0, no `FATAL` / `Bungled` / `ERROR:` lines. |
| **TC-3.2: No Empty ACLs** | An `acl X dstdomain "file"` whose file has no entries parses fine but can never match. | Grep parse output for `empty ACL`. | No empty-ACL warnings. This is the failure mode that makes a broken `bump_domains.acl` or `domains_*.acl` invisible. |
| **TC-3.3a: `rules.acl` Present** | Web UI generated the device rules. | `cat /etc/squid/configs/rules.acl`. | Contains the `AUTO-GENERATED BY SQUID WEB UI` banner. |
| **TC-3.3b: Policy ↔ ACL Cross-check** | Every configured device maps to an ACL. | Compare IPs from `GET /api/policies` against `acl src_dev_<ip> src <ip>` lines. | Each device with blocklists has a matching `src` ACL. |
| **TC-3.4a: `ssl_bump.acl` Present** | Dynamic bump rules generated. | `cat /etc/squid/configs/ssl_bump.acl`. | Contains the `DYNAMIC SSL BUMP RULES` banner. |
| **TC-3.4b: No Dangling ACL Refs** | `ssl_bump.acl` references names *defined in* `rules.acl`. | Extract every ACL name used by `ssl_bump bump …` and require an `acl <name>` definition in `rules.acl`. | Zero dangling references. A dangling name aborts Squid on reload and takes the proxy down. |
| **TC-3.4c: Bump Coverage** | A device with blocked lists must have a bump rule. | Compare policies with blocked lists against `ssl_bump bump` lines. | At least one bump rule whenever any device has blocked categories — otherwise the HTTPS block page can never render. |
| **TC-3.4d: Bypass Invariant** | Every `http_access deny !CONNECT <src> <list>` must have a matching SNI-aware `ssl_bump bump` rule. | Map each HTTP `list_*` ACL to its `sni_list_*` counterpart and cross-reference both files. | Zero unmatched denies. The `!CONNECT` scoping deliberately lets the CONNECT through so Squid can bump and render the block page on the decrypted request; without the bump rule the CONNECT falls through to `http_access allow localnet` and **the site becomes fully reachable**. This check must never fail. |
| **TC-3.4e: Transparent SNI Safety** | Selective bump rules can match a transparent TLS connection after ClientHello peek. | Inspect every `ssl_bump bump <src> <category>` rule. | Category ACL is `sni_list_*` or `sni_path_dom_*` and is declared as `ssl::server_name`. Reusing `dstdomain` works through explicit port 3128 but silently splices transparent port 3130. |
| **TC-3.4f: Scheduled Native TLS** | Categories inside an active allow window are not unnecessarily decrypted. | Match every `http_access allow <src> <list> <time>` to `ssl_bump splice <src> <sni-list> <time>`. | Every scheduled allow has a matching splice before its fallback bump. This preserves native transports such as YouTube `googlevideo.com` UMP playback. |
| **TC-3.5a: `bump_domains.acl` ↔ Blocklists** | The generated bump list matches its source. | Derive the expected set from `block-lists/*.txt` lines containing `/`, diff against the container's file. | Exact match; an empty file is correct when no blocklist has a path rule. The previous hardcoded "must contain `steamcommunity.com`" assertion failed on a correct system and hid the fact that the file was stale. |
| **TC-3.5b: No Plain-Domain Leak** | Selective bumping must stay selective. | Any entry not derivable from a `domain/path` blocklist line is a leak. | No plain blocklist domain in `bump_domains.acl` — a leak would decrypt that domain for **all** devices. |
| **TC-3.5c: `.conf` ↔ `.acl` Agreement** | `bump_domains.conf` holds the `acl` + `ssl_bump` directives; `squid.conf` includes it rather than declaring them inline. | Check whether the `.conf` declares `acl bump_domains` and compare against the `.acl` entry count. | Declares the ACL when the list is non-empty; declares nothing when it is empty. A declaration over an empty file parses fine but can never match. |
| **TC-3.6: CA Cert Validity** | Local CA exists and is not near expiry. | `openssl x509 -checkend 2592000` on `certs/squid-ca.pem`. | Valid for at least 30 more days; expiry date is printed. |

---

### Suite 4: Network Interception & Selective SSL Bumping

| Test Case | Description | Execution | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-4.0: Remote Ubuntu Client** | Test client answers over SSH and is Ubuntu Linux. | Read `ID` from the remote client's `/etc/os-release` using non-interactive SSH. | SSH succeeds and `ID=ubuntu`; no local-client fallback is available. |
| **TC-4.1: Allowed HTTP** | Unblocked domain over HTTP. | `curl http://example.com` | 200 / 3xx. |
| **TC-4.2: Allowed HTTPS (spliced)** | Unblocked HTTPS is passed through raw. | `curl -k https://example.com`, `https://www.wikipedia.org` | 200 / 3xx. |
| **TC-4.3: Adult HTTPS Transparent Block** | Regression for selective SSL bumping on the target's real adult policy. | Before policy mutation, request `https://www.pornhub.com/` when `adult.txt` is in `always_block`. | 403 + parental block page. A tunneled 200 exposes a transparent SNI matching bypass. |
| **TC-4.4a: Blocked URL Path** | Deep path inspection blocks `domain/path`. | Select a path-only rule from a blocklist active for the target device. | 403 + parental block page. **Skipped with a WARN when no active category has a non-redundant path rule.** |
| **TC-4.4b: Base Domain Allowed** | The base domain of a path-only rule stays reachable. | `curl -k https://<domain>/` after excluding rules whose domain is also covered by a plain-domain entry. | 200 / 3xx with no block page. |
| **TC-4.5: Strict CA Trust** | Root CA is installed on the client. | `curl https://example.com` **without** `-k`. | Clean handshake, no `SSL certificate problem`. |
| **TC-4.6a: Spotify 4070 (router)** | Router marks TCP 4070. | `iptables -t mangle -L SQUID_MARK`. | 4070 covered. |
| **TC-4.6b: Spotify 4070 (container)** | Container redirects 4070. | Container NAT `PREROUTING`. | `4070 → 3130`. Asserted separately from the router half so a failure names the broken side. |
| **TC-4.7a: YouTube QUIC Allow** | YouTube keeps using QUIC for playback. | FORWARD `ACCEPT` for the `youtube_quic` ipset (or the CIDR fallback). | Rule present. |
| **TC-4.7b: QUIC Bypass Prevention** | All *other* UDP/443 is rejected so browsers fall back to TCP and Squid can see the traffic. | FORWARD `REJECT` udp/443 per intercepted host. | Rule present for every host in `proxy-hosts.conf`. Without it, any site bypasses the proxy over QUIC. |
| **TC-4.8a/b: Video Lifecycle** | Dynamic Web UI policy change takes effect. | `POST /api/policies` unblocked → test Vimeo → blocked → test Vimeo → restore. | Unblocked: 200 with no block page. Blocked: 403 + block page. |
| **TC-4.9a: Block Page over HTTP** | Block page payload. | Blocked domain over HTTP. | 403, `X-Squid-Error: ERR_ACCESS_DENIED`, `Webpage Blocked` title, parental message. |
| **TC-4.9b: Block Page over HTTPS** | The page users actually see. | Same domain over HTTPS (bumped). | Same four signatures. Previously only the HTTP body was checked. |
| **TC-4.10: Policy Restore** | The suite leaves no residue. | Snapshot before mutation; restore via an `EXIT`/`INT`/`TERM` trap; canonicalize with `jq -S -c`, then compare. | Live policies semantically identical to the pre-test snapshot; failures appear in the named summary. |

#### Interpreting a TLS protocol error

If a "blocked" test reports `wrong version number` / `TLS connect error`, the suite emits a **WARN**, not a PASS. That signature means Squid sent a plaintext HTTP error down a socket the client is speaking TLS on — the request was *denied but never bumped*, so the user gets a browser TLS error instead of the parental block page. Check that `ssl_bump.acl` covers that device + category.

---

### Suite 5: Management CLI

| Test Case | Description | Verification Logic | Expected Outcome |
| :--- | :--- | :--- | :--- |
| **TC-5.1: `dump-config`** | CLI reaches the container and parses the config. | Assert on Squid's own `Processing Configuration File` output, **not** on `squid-mgmt.sh`'s unconditional `Config dumped.` echo. | Real parser output, no `FATAL`. |
| **TC-5.2: `catlogs`** | CLI retrieves the access log and reports evidence for the selected test client. | Delete `logs/access.log`, run `catlogs`, assert the file was recreated and `Saved local log snapshot` was printed, then filter Squid's third log field by `TARGET_CLIENT_IP`. | Matching client entries ⇒ PASS and only that client's last 15 lines are printed; non-empty global log with no client match ⇒ WARN; empty log ⇒ WARN. This prevents unrelated workstation traffic from being presented as vm-ubuntu test evidence. |

---

## 4. How to Run the Test Suite

```bash
# Default run (targets vm-ubuntu at 192.168.8.30 via SSH — full transparent-intercept path)
./debug/debug-proxy.sh

# Run targeting a different remote Ubuntu client
./debug/debug-proxy.sh --client-ip 192.168.1.11

# Run with container redeployment before testing
./debug/debug-proxy.sh --redeploy
```

---

## 5. Test Suite Output Format

Colour-coded when stdout is a terminal, plain text when redirected to the log file:

- `[PASS]` (green): assertion succeeded.
- `[FAIL]` (red): assertion failed. All failures are re-listed in the summary block.
- `[WARN]` (yellow): the condition could not be asserted in this mode, or a non-fatal anomaly was detected.
- `[INFO]` (cyan): diagnostic context.

The run ends with `exit 1` if any assertion failed.

---

## 6. Known Limitations

1. **Only remote Ubuntu clients are supported.** The default is vm-ubuntu at
   `192.168.8.30`. A `--client-ip` override must also identify an Ubuntu host with
   working key-based SSH. This keeps every traffic assertion on the router's
   transparent-interception path.
2. **TC-4.4 needs an active, non-redundant path rule.** Deep URL path inspection
   can only be tested when the target policy selects a blocklist containing a
   `domain/path` entry whose base domain is not also covered by a plain-domain
   entry. Otherwise the test reports a WARN and is skipped.
3. **Suite 2 assumes open API access.** Once `is_authenticated()` in
   `webui/app.py` is restored to a real session check (which TC-2.7 exists to
   force), the suite will need a login step (`POST /api/login` + cookie jar)
   before the other Suite 2 and Suite 4 policy calls will work.
