# Product Specification & Architecture Document: Squid Proxy Center Web UI

> **Document Version:** 1.0.0  
> **Last Updated:** 2026-08-09  
> **Status:** Active / User Editable Specification  
> **Target Path:** `personal/home-network/squid/webui`

---

## 1. Product Overview & Objectives

**Squid Proxy Center Web UI** is a lightweight, responsive web management interface for managing transparent network proxying, SSL/TLS interception onboarding, and domain/category access control rules powered by a Squid Proxy container and an ASUS Router firewall daemon.

### Key Objectives
1. **Client Onboarding & CA Trust:** Provide zero-friction download of the internal Root CA certificate (`squid-ca.crt` / `squid-ca.pem`) alongside step-by-step setup guides for Windows and Ubuntu Linux clients to prevent HSTS and SSL warnings.
2. **Access Control Management:** Allow administrators to configure per-device domain blocklists and scheduled access restrictions (e.g., blocking social media during school/work hours).
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
│  - Ubuntu Linux Guide                      - Active ACL Rules Matrix        │
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
  - Allows selecting which domain blocklists (`social.txt`, `gaming.txt`, `streaming.txt`, `adult.txt`, etc.) will be active for the device during blocked time slots.
- **Interactive 30-Minute Weekly Schedule Matrix:**
  - **Grid Format:** 7 columns (`Sun`, `Mon`, `Tue`, `Wed`, `Thu`, `Fri`, `Sat`) x 48 rows (30-minute intervals from `00:00 - 00:30` to `23:30 - 00:00`).
  - **Mouse Drag Selection:** Click and drag across grid cells to visually set time slots as Blocked (Red gradient `🚫`) or Allowed (Translucent).
  - **Row & Column Toggles:** Click any day header or time slot header to toggle full columns or rows instantly.
  - **Quick Presets:** One-click presets for `Block All`, `Allow All`, `Night (10PM-7AM)`, `School (8AM-4PM)`, and `Weekends`.
- **One-Click Apply & Hot-Reload (After Schedule Matrix):**
  - Prominent "Apply Configuration to Squid Proxy" button converts all active device policies into Squid ACL statements inside `rules.acl` and triggers container reconfiguration (`squid -k reconfigure`).

### 3.3 Security & Authentication
- **NAS Credential Verification:** Checks submitted admin passwords against mounted QNAP shadow password hashes (`md5_crypt`, `sha512_crypt`, `sha256_crypt`) with paramiko SSH fallback.
- **Session Management:** Secure HTTP-only Flask session cookies.

---

## 4. REST API Endpoint Specification

| Endpoint | Method | Auth | Description |
| :--- | :--- | :--- | :--- |
| `/api/auth/status` | `GET` | Public | Returns current authentication state and username. |
| `/api/auth/login` | `POST` | Public | Authenticates admin using username/password. |
| `/api/auth/logout` | `POST` | Public | Clears admin session. |
| `/api/devices` | `GET` | Admin | Returns list of devices parsed from `devices.list`. |
| `/api/blocklists` | `GET` | Admin | Lists available blocklist category files. |
| `/api/policies` | `GET` | Admin | Returns all saved per-device policies & 30-min schedule matrices. |
| `/api/policies` | `POST` | Admin | Saves/updates per-device blocklist & 30-min matrix policy. |
| `/api/apply` | `POST` | Admin | Compiles all device policies to `rules.acl` and reloads Squid daemon. |
| `/download/cert.<ext>` | `GET` | Public | Downloads Root CA certificate (`.crt` or `.pem`). |

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
