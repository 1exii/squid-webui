# Product Specification & Architecture Document: Squid Proxy Center Web UI

> **Document Version:** 1.2.0
> **Last Updated:** 2026-08-22
> **Status:** Active / User Editable Specification  
> **Target Path:** `personal/home-network/squid/webui`

---

## 1. Product Overview & Objectives

**Squid Proxy Center Web UI** is a lightweight, responsive web management interface for managing proxy auto-configuration, transparent network fallback, SSL/TLS interception onboarding, and domain/category access control rules powered by a Squid Proxy container and an ASUS Router firewall daemon.

### Key Objectives
1. **Client Onboarding, PAC & CA Trust:** Provide a fail-closed browser PAC file, automated Windows/Ubuntu installers, internal Root CA downloads (`squid-ca.crt` / `squid-ca.pem`), and setup guides. Explicit browser proxying avoids the mandatory intercepted-CONNECT destination verification failures that occur with rapidly rotating CDN DNS addresses.
2. **Access Control Management:** Allow administrators to configure per-device domain blocklists, scheduled access restrictions (e.g., blocking social media during school/work hours), and temporary single-day ("Today Only") rule overrides.
3. **Seamless Deployment:** Provide one-click compilation of rules into Squid `rules.acl` format and hot-reload the Squid daemon without interrupting general network traffic.
4. **Secure Administration:** Authenticate admin users directly against QNAP NAS system shadow password hashes or SSH authentication.

---

## 2. Information Architecture & Navigation

The Web UI features a modern, single-page application (SPA) layout with dark glassmorphism styling.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 🦑 Squid Proxy Center                           [📖 Onboarding] [⚙️ Admin]   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [VIEW 1: Client Onboarding & Certs]       [VIEW 2: Access Control Admin]   │
│  - Hero CA Download Card                   - System Overview Metrics        │
│  - Windows Installation Guide              - Device & Host Status           │
│  - Ubuntu Linux Guide                      - Dual-Mode Schedule (Weekly/Today)│
│                                            - Active ACL Rules Matrix        │
│                                            - Add / Edit / Delete Modal      │
│                                            - One-Click "Apply & Reload"     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Top Navigation Bar
- **Brand Identity:** Logo (`🦑`), Title ("Squid Proxy Center").
- **View Switches:**
  - `📖 Client Onboarding & Certs` (Public Access)
  - `⚙️ Access Control Admin` (shown automatically only to allowlisted admin client IPs; other clients must explicitly visit `/admin`)
  - `📊 Website Activity` (admin-only daily per-client website and category analysis)
- **User Status Badge:** Displays current authenticated user (e.g., `👤 admin`) and Login/Logout action button.

---

## 3. Current Feature Specifications

### 3.1 Client Onboarding Module (Public)
- **Root CA Downloads:**
  - `squid-ca.crt`: Binary X.509 certificate for Windows / macOS / iOS trust stores.
  - `squid-ca.pem`: PEM ASCII format for Linux trust stores (`/usr/local/share/ca-certificates/`).
- **Interactive Guides:**
  - **Windows Guide:** Automated PowerShell machine CA trust, current-user Windows PAC configuration, machine-level Chrome `ProxySettings` policy installation, manual setup-script configuration, and browser trust guidance.
  - **Ubuntu Linux Guide:** Automated CA/PAC installation, `update-ca-certificates`, a managed Chrome/Chromium `ProxySettings` policy, GNOME PAC configuration, and NSS database import (`certutil`).
- **Proxy Auto-Config:** Public `/proxy.pac` sends Internet traffic to the deployment-configured explicit Squid proxy, sends loopback/private/local-name destinations direct, and deliberately omits a `DIRECT` fallback for Internet requests.
- **Per-Client QUIC Fallback:** Every controlled client rejects general UDP/443 proxy bypass. Clients carrying the optional `no_quic` flag in `proxy-hosts.conf` also reject Google/YouTube QUIC, forcing HTTP/3 traffic onto TCP so Squid can enforce category policies and render the custom HTTPS block page; unflagged clients retain the YouTube QUIC performance exception.
- **Per-Client WARP Blocking:** Clients carrying the independent `no_vpn` flag reject Cloudflare WARP ingress endpoints and have existing matching tunnel state removed during router deployment, preventing full-tunnel WARP from hiding destination traffic from Squid. This flag is WARP-specific rather than a claim to detect every possible VPN protocol.

### 3.2 Access Control & Device Policy Manager (Admin Only)
- **Dynamic Device Tab Navigation (`devices.list`):**
  - Reads target devices from `devices.list` (extracted from Pi-hole name lists).
  - Renders horizontal device tabs (with category icons `📱` Phone, `💻` Laptop, `🖥️` PC, `📱` Tablet) and a real-time search box.
  - Automatically updates tabs whenever `devices.list` is edited and the Web UI is redeployed.
- **Three-State Category Policy (Before Schedule Matrix):**
  - **Always Block** checkboxes deny selected categories at all times and take highest precedence.
  - **Always Allow** checkboxes permit selected categories at all times, unless overlapping content is also matched by an Always Block category.
  - **Default Block** has no selection checkbox. It is automatically the complement of Always Block and Always Allow, so every remaining category is blocked unless its timetable grants an unblock window.
  - An Always Block category is hidden from Always Allow and Default Block. An Always Allow category is hidden from Default Block but remains visible in Always Block so it can be promoted directly to the higher-priority policy.
  - Moving a category out of either explicit list automatically returns it to Default Block.
  - Blocklist files (`block-lists/*.txt`) are dynamically parsed by `parse_blocklists()` into clean `dstdomain` ACLs (`domains_<bl>.acl`) and URL path regex ACLs (`urlpath_regex`).
- **Interactive 30-Minute Dual-Mode Schedule Matrix (Weekly & Today Overwrite):**
  - **Dual Mode Pill Toggle:** Switch seamlessly between `📅 Weekly` (7×48 grid) and `📆 Today Only` (1×48 grid) editing modes.
  - **Weekly Schedule Grid:** 7 columns (`Sun`, `Mon`, `Tue`, `Wed`, `Thu`, `Fri`, `Sat`) × 48 rows (30-minute intervals from `00:00 - 00:30` to `23:30 - 00:00`) for defining recurring weekly unblock/block time windows.
  - **Today-Only Overwrite Grid:** 1 column (`Today` / single day header with current day name) × 48 rows for configuring ad-hoc, single-day unblock overrides (`unblock_today`) without altering the permanent weekly schedule.
  - **Schedule Merging Logic (`merge_today_into_weekly`):** Today-only unblock slots dynamically overlay onto the device's weekly matrix for the active day during ACL compilation, granting temporary access without modifying regular weekly policies.
  - **Automated Midnight Expiration:** Today-only overrides are stamped with `today_date` (ISO date string). A daemon thread (`daily_expiration_task`) checks hourly and automatically clears stale today slots at midnight, reverting the device to standard weekly policies.
  - **Mouse Drag Selection:** Click and drag across grid cells in either view to visually set time slots as Blocked (Red gradient `🚫`) or Allowed (Translucent).
  - **Row & Column Toggles:** Click any day header or time slot header to toggle full columns or rows instantly.
  - **Quick Presets:** One-click presets for `Block All`, `Allow All`, `Night (10PM-7AM)`, `School (8AM-4PM)`, and `Weekends`.
- **One-Click Save & Apply Pipeline:**
  - Prominent "Save & Apply" button saves device policies via `POST /api/policies`, compiles per-device conditional ACL rules into `rules.acl`, compiles per-device dynamic SSL bump rules into `ssl_bump.acl`, and triggers Squid reload via Docker Socket SIGHUP signaling (`POST /api/apply`).
- **Per-Device SSL Bumping & Auto-Bumping Blocked Sites (`ssl_bump.acl`):**
  - Blocked categories and path rules configured for a target device are automatically compiled into `ssl_bump.acl` using dedicated TLS SNI ACLs (`ssl_bump bump src_dev_<ip> sni_list_<bl>`). `dstdomain` remains reserved for HTTP access checks; it cannot reliably identify the hostname during transparent TLS interception.
  - Allows Squid to intercept TLS handshakes on blocked domains and render the customized **Parental Control Block Page** (`ERR_ACCESS_DENIED`) over HTTPS without browser protocol or connection reset errors.
  - Traffic to non-blocked domains and all traffic from unrestricted devices is spliced (`ssl_bump splice all`) with raw TLS passthrough (zero certificate overhead, native end-to-end encryption).
- **Decoupled Global SSL Bumping (`bump_domains.acl`):**
  - Global URL path-based SSL Bumping is generated by `configs/generate_bump_domains.py` during container startup to support deep URL path matching across all devices.

### 3.3 Security & Authentication
- **Trusted Admin Clients:** Requests from `ADMIN_CLIENT_IPS` can use the Admin UI and protected APIs without a password and land on the Admin view by default.
- **Hidden Admin Entry Point:** Other clients see only onboarding at `/`; visiting `/admin` explicitly reveals the Admin login flow.
- **NAS Credential Verification:** Checks submitted admin passwords against mounted QNAP shadow password hashes (`md5_crypt`, `sha512_crypt`, `sha256_crypt`) with paramiko SSH fallback.
- **Session Management:** Secure HTTP-only Flask session cookies.
- **Protected APIs:** Clients outside `ADMIN_CLIENT_IPS` must have an authenticated session to read or modify Admin data.

### 3.4 Daily Website Activity (Admin Only)
- Reads the active and numbered rotated Squid native `access.log` files from a read-only WebUI container mount.
- Lets an administrator select a configured client and any retained date from the last 30 days.
- Rotates Squid logs automatically at local midnight and keeps 30 numbered daily generations on the persistent log volume.
- Groups hostname-visible traffic into website/service totals by default. Ordinary subdomains roll up to their registrable domain, while known multi-domain services such as YouTube, Netflix, Roblox, Spotify, Facebook, Instagram, and TikTok also include their first-party CDN/API domains.
- Each website row can expand into its contributing domain names with per-domain time, category, request, blocked-request, and last-seen details.
- Estimates active time by assigning the gap until the next proxy request to the current website. Gaps longer than five minutes count as a 30-second tail. This is labeled as an estimate because proxy traffic includes background services and cannot identify foreground screen time.
- Omits IP-only destinations because they cannot be reliably presented or categorized as websites.

### 3.5 Configuration Change Audit (Admin Only)
- Every semantic policy change from `POST /api/policies` is appended to the persistent `configuration_audit.jsonl` file on the shared Squid config volume; identical auto-save requests do not create noise.
- Each event records the server-local timestamp, NAS username or trusted-admin-client identity, source admin IP, success state, affected devices and fields, and exact before/after policy values.
- Automatic midnight expiration is recorded as a system actor. Failed ACL compilation is also recorded because `device_policies.json` was changed even when generated ACL files were rolled back.
- The API combines two or more changes into one displayed entry when they have the same authenticated identity, source admin-client IP, and single target device and all occur within two minutes of the first change, even if another device was edited between them. Raw JSONL events remain append-only and unmodified; automatic system events and multi-device changes are never combined.
- The authenticated Change Log view displays the newest 100 entries with a lazy-rendered, side-by-side JSON comparison. Removed values are highlighted red and added values green while unchanged lines remain aligned. `SQUID_AUDIT_LOG` can override the storage path.

---

### 3.6 Critical User Journeys (CUJs)

#### 🎯 CUJ 1: Permanent 24/7 Block (`Always Block` Subset)
- **User Goal:** Unconditionally block specific high-risk category lists (e.g. `adult.txt`, `gambling.txt`) on a target device 24/7, bypassing any time-based schedule matrices.
- **User Experience & Admin Action:**
  1. Admin opens Web UI and selects the target device tab (e.g. `Child Phone - 192.0.2.50`).
  2. Under the **Always Block** category list, admin checks `adult.txt` and `gambling.txt`.
  3. Admin clicks **Save & Apply**.
- **System & ACL Behavior:**
  - `webui/app.py` writes `always_block: ["adult.txt", "gambling.txt"]` into `device_policies.json`.
  - Unconditional `http_access deny` rules are placed at the top of the device's rule block in `rules.acl`:
    ```acl
    # Always Block — Child Phone
    http_access deny src_dev_192_168_1_50 list_adult_txt
    http_access deny src_dev_192_168_1_50 list_gambling_txt
    ```
  - Traffic to these categories is blocked continuously regardless of day or time.

#### ⏰ CUJ 2: Time-Scheduled Category Control (`Default Block` + 30-Min Weekly Table)
- **User Goal:** Block entertainment categories (e.g. `gaming.txt`, `socialmedia.txt`) by default, but allow access during specific recurring weekly time windows (e.g. Mon-Fri 16:00 - 20:00).
- **User Experience & Admin Action:**
  1. Admin selects the device tab (`Child Phone`).
  2. Admin leaves `gaming.txt` and `socialmedia.txt` out of both **Always Block** and **Always Allow**, so they appear automatically under **Default Block (Scheduled Unblock Windows)**.
  3. Admin ensures schedule mode is set to **`📅 Weekly`** (7×48 grid).
  4. Admin drags mouse across grid cells for `Mon`–`Fri` between `16:00` and `20:00` to set them as Allowed (translucent cyan), leaving all other time slots Blocked (red gradient).
  5. Admin clicks **Save & Apply**.
- **System & ACL Behavior:**
  - `webui/app.py` stores the 7×48 boolean matrix in `unblock_weekly`.
  - `extract_allow_ranges()` groups contiguous allowed slots into Squid `time` ACL definitions and compiles conditional allow/deny rules:
    ```acl
    # Default Block (unblock windows): gaming.txt — Child Phone
    acl time_allow_192_168_1_50_0 time MTWTF 16:00-20:00
    http_access allow src_dev_192_168_1_50 list_gaming_txt time_allow_192_168_1_50_0
    http_access deny src_dev_192_168_1_50 list_gaming_txt
    ```

#### ✅ CUJ 3: Permanent Access (`Always Allow` Subset)
- **User Goal:** Keep selected categories available regardless of the Default Block timetable.
- **User Experience & Admin Action:** Admin checks categories under **Always Allow**, then saves and applies the policy.
- **System & ACL Behavior:** The category is removed from Default Block and receives an unconditional `http_access allow` rule after Always Block rules but before scheduled Default Block rules.

#### 🎁 CUJ 4: Ad-Hoc Temporary Access Bonus ("Give Kids 30 Min Extra Gaming Time Today")
- **User Goal:** Give a child an extra 30-minute gaming bonus today (e.g., `20:30 - 21:00`) outside their normal weekly allowed window, without altering their permanent recurring weekly schedule.
- **User Experience & Admin Action:**
  1. Admin opens the Web UI and selects the child's device tab.
  2. Admin switches the schedule mode toggle from `📅 Weekly` to **`📆 Today Only`** (displaying a 1×48 single column for the current day).
  3. Admin clicks/drags the `20:30 - 21:00` slot in the Today column to mark it as Allowed.
  4. Admin clicks **Save & Apply**.
- **System & ACL Behavior:**
  - `webui/app.py` stores slot index 41 (`20:30 - 21:00`) as `True` in `unblock_today` alongside `today_date: "2026-08-14"`.
  - `merge_today_into_weekly()` overlays `unblock_today` onto today's row in the weekly matrix during ACL compilation, adding `20:30 - 21:00` to today's active allowed `time` ACL rule in `rules.acl`.
  - At midnight, `daily_expiration_task` detects the date change and automatically resets `unblock_today` to all-`False`, returning the child's device to standard weekly policies without requiring any manual cleanup by the parent.

---

## 4. REST API Endpoint Specification

| Endpoint | Method | Auth | Description |
| :--- | :--- | :--- | :--- |
| `/api/auth/status` | `GET` | Public | Returns current authentication state and username. |
| `/api/auth/login` | `POST` | Public | Authenticates admin using username/password. |
| `/api/auth/logout` | `POST` | Public | Clears admin session. |
| `/api/devices` | `GET` | Admin | Returns list of devices parsed from `devices.list`. |
| `/api/activity?date=<YYYY-MM-DD>&client_ip=<IPv4>` | `GET` | Admin | Returns daily categorized website activity and estimated active time for one client. |
| `/api/audit-log?limit=<1-500>` | `GET` | Admin | Returns newest-first append-only Squid configuration audit events. |
| `/api/blocklists` | `GET` | Admin | Lists available blocklist category files. |
| `/api/policies` | `GET` | Admin | Returns `always_block`, `always_allow`, and the automatically materialized `default_block` schedule entries for each device. |
| `/api/policies` | `POST` | Admin | Normalizes Default Block as the complement of the explicit lists, expires stale today overrides, and compiles Squid ACLs. |
| `/api/apply` | `POST` | Admin | Triggers Squid reload via Docker daemon Unix socket (`SIGHUP` signal to `squid-proxy`). |
| `/download/cert.<ext>` | `GET` | Public | Downloads Root CA certificate (`.crt` or `.pem`). |
| `/proxy.pac` | `GET` | Public | Fail-closed browser PAC file: private/local destinations direct, Internet traffic through explicit Squid port 3128. |
| `/download/install-ubuntu.sh` | `GET` | Public | Automated CA and PAC installation shell script for Ubuntu Linux clients. |
| `/download/install-windows.ps1` | `GET` | Public | Automated machine CA trust, current-user Windows PAC configuration, and machine-level Chrome `ProxySettings` policy installation script. |

---

## 5. Design System & Styling Guidelines

- **Color Palette:**
  - Background: Dark Teal/Slate `#0B132B` / `#1C2541`
  - Accent / Primary: Vibrant Cyan `#48CAE4` / `#00B4D8`
  - Secondary: Deep Purple/Indigo `#3A0CA3` / `#7209B7`
  - Glassmorphism: `backdrop-filter: blur(12px)`, `background: rgba(255, 255, 255, 0.05)`, subtle border glowing.
- **Typography:** `Inter`, system UI font fallback.

---

## 6. User Customization & Extension Backlog

> ✏️ **Edit this section!** Add, update, or re-order features below to tell the AI assistant what changes you want implemented in the Web UI.

### Proposed Feature Additions (Drafting Area)

#### 🎨 Feature A: UI / UX Enhancements
- [ ] **Theme Switcher:** Add light mode / high-contrast toggle.
- [ ] **Dashboard Overview Cards:** Show active client count, total blocked domains count, and current proxy container uptime.
- [ ] **Search & Filter:** Add real-time filtering for rules and onboarding guides.

#### 📊 Feature B: Traffic Monitoring & Analytics
- [x] **Daily Client Website Activity:** Categorized hostname list with request counts, blocked counts, filters, and estimated active time.
- [ ] **Live Squid Log Streamer:** Real-time log viewer (`access.log`) showing allowed vs blocked requests via WebSocket or SSE.
- [ ] **Top Blocked Domains Chart:** Graphical chart showing top 10 blocked domain queries today.

#### ⚙️ Feature C: Advanced Access Control Rules
- [ ] **Custom Domain White/Blacklist:** Allow adding quick ad-hoc domain overrides directly in the UI without editing text files.
- [ ] **Temporary Bypass ("Pause Block"):** One-click button to temporarily pause access control rules on a device for 15, 30, or 60 minutes.
- [ ] **Multi-User Role Management:** Add read-only viewer accounts vs full admin accounts.

#### 📱 Feature D: Mobile & Responsive Layout
- [ ] **Mobile Touch Optimization:** Refine modal dialogs and table layouts for smartphone screens.

---

## 7. Instructions for Requesting Implementation Updates

When you finish updating this file:
1. Save your changes to this file (`PRODUCT_SPEC.md`).
2. Message the AI assistant with a prompt like:
   > *"I updated `personal/home-network/squid/webui/PRODUCT_SPEC.md`. Please update the Web UI implementation to reflect the changes in Section 6."*
