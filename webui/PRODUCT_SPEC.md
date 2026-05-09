# Product Specification & Architecture Document: Squid Proxy Center Web UI

> **Document Version:** 1.1.0  
> **Last Updated:** 2026-08-14  
> **Status:** Active / User Editable Specification  
> **Target Path:** `personal/home-network/squid/webui`

---

## 1. Product Overview & Objectives

**Squid Proxy Center Web UI** is a lightweight, responsive web management interface for managing transparent network proxying, SSL/TLS interception onboarding, and domain/category access control rules powered by a Squid Proxy container and an ASUS Router firewall daemon.

### Key Objectives
1. **Client Onboarding & CA Trust:** Provide zero-friction download of the internal Root CA certificate (`squid-ca.crt` / `squid-ca.pem`) alongside step-by-step setup guides for Windows and Ubuntu Linux clients to prevent HSTS and SSL warnings.
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
  - `⚙️ Access Control Admin` (Protected by Authentication)
- **User Status Badge:** Displays current authenticated user (e.g., `👤 admin`) and Login/Logout action button.

---

## 3. Current Feature Specifications

### 3.1 Client Onboarding Module (Public)
- **Root CA Downloads:**
  - `squid-ca.crt`: Binary X.509 certificate for Windows / macOS / iOS trust stores.
  - `squid-ca.pem`: PEM ASCII format for Linux trust stores (`/usr/local/share/ca-certificates/`).
- **Interactive Guides:**
  - **Windows Guide:** Step-by-step instructions for `Import-Certificate` via PowerShell, `certlm.msc` GUI setup, Edge/Chrome HSTS cache clearing (`chrome://net-internals/#hsts`), and Firefox custom trust settings.
  - **Ubuntu Linux Guide:** CLI commands for `update-ca-certificates`, `curl` CA bundle setup, and Chrome/Firefox NSS database import (`certutil`).

### 3.2 Access Control & Device Policy Manager (Admin Only)
- **Dynamic Device Tab Navigation (`devices.list`):**
  - Reads target devices from `devices.list` (extracted from Pi-hole name lists).
  - Renders horizontal device tabs (with category icons `📱` Phone, `💻` Laptop, `🖥️` PC, `📱` Tablet) and a real-time search box.
  - Automatically updates tabs whenever `devices.list` is edited and the Web UI is redeployed.
- **Blocker-Lists Checkbox Selection (Before Schedule Matrix):**
  - Displayed before the schedule table.
  - Allows selecting which domain blocklists (`socialmedia.txt`, `gaming.txt`, `videos.txt`, `adult.txt`, etc.) will be active for the device during blocked time slots.
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
  - Blocked categories and path rules configured for a target device are automatically compiled into `ssl_bump.acl` (`ssl_bump bump src_dev_<ip> list_<bl>`).
  - Allows Squid to intercept TLS handshakes on blocked domains and render the customized **Parental Control Block Page** (`ERR_ACCESS_DENIED`) over HTTPS without browser protocol or connection reset errors.
  - Traffic to non-blocked domains and all traffic from unrestricted devices is spliced (`ssl_bump splice all`) with raw TLS passthrough (zero certificate overhead, native end-to-end encryption).
- **Decoupled Global SSL Bumping (`bump_domains.acl`):**
  - Global URL path-based SSL Bumping is generated by `configs/generate_bump_domains.py` during container startup to support deep URL path matching across all devices.

### 3.3 Security & Authentication
- **NAS Credential Verification:** Checks submitted admin passwords against mounted QNAP shadow password hashes (`md5_crypt`, `sha512_crypt`, `sha256_crypt`) with paramiko SSH fallback.
- **Session Management:** Secure HTTP-only Flask session cookies.

---

### 3.4 Critical User Journeys (CUJs)

#### 🎯 CUJ 1: Permanent 24/7 Block (`Always Block` Subset)
- **User Goal:** Unconditionally block specific high-risk category lists (e.g. `adult.txt`, `gambling.txt`) on a target device 24/7, bypassing any time-based schedule matrices.
- **User Experience & Admin Action:**
  1. Admin opens Web UI and selects the target device tab (e.g. `Child Phone - 192.168.1.50`).
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
  2. Under **Default Block (Scheduled Unblock Windows)**, admin selects `gaming.txt` and `socialmedia.txt`.
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

#### 🎁 CUJ 3: Ad-Hoc Temporary Access Bonus ("Give Kids 30 Min Extra Gaming Time Today")
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
| `/api/blocklists` | `GET` | Admin | Lists available blocklist category files. |
| `/api/policies` | `GET` | Admin | Returns all saved per-device policies & schedule matrices (including `unblock_weekly`, `unblock_today`, and `today_date`). |
| `/api/policies` | `POST` | Admin | Saves per-device policies (auto-expiring stale today overrides), compiles clean `domains_<bl>.acl` files and `rules.acl`. |
| `/api/apply` | `POST` | Admin | Triggers Squid reload via Docker daemon Unix socket (`SIGHUP` signal to `squid-proxy`). |
| `/download/cert.<ext>` | `GET` | Public | Downloads Root CA certificate (`.crt` or `.pem`). |
| `/download/install-ubuntu.sh` | `GET` | Public | Automated CA installation shell script for Ubuntu Linux clients. |

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
