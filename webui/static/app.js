/**
 * Squid Web UI - Main Application Script
 * Handles authentication, device selection, schedule matrix, and real-time rules preview.
 */
document.addEventListener('DOMContentLoaded', () => {

    // ──────────────────────────────────────────────────────────────
    // DOM REFERENCES
    // ──────────────────────────────────────────────────────────────
    const navTabOnboarding     = document.getElementById('nav-tab-onboarding');
    const navTabAdmin          = document.getElementById('nav-tab-admin');
    const onboardingScreen     = document.getElementById('onboarding-screen');
    const adminScreen          = document.getElementById('admin-screen');
    const userBadge            = document.getElementById('user-badge');
    const currentUserSpan      = document.getElementById('current-user');
    const authActionBtn        = document.getElementById('auth-action-btn');

    const guideTabWindows      = document.getElementById('guide-tab-windows');
    const guideTabUbuntu       = document.getElementById('guide-tab-ubuntu');
    const guideContentWindows  = document.getElementById('guide-content-windows');
    const guideContentUbuntu   = document.getElementById('guide-content-ubuntu');

    const authModal            = document.getElementById('auth-modal');
    const authModalClose       = document.getElementById('auth-modal-close');
    const loginForm            = document.getElementById('login-form');
    const loginError           = document.getElementById('login-error');

    // Admin workspace elements
    const top5DevicesButtons   = document.getElementById('top5-devices-buttons');
    const allDevicesDropdown   = document.getElementById('all-devices-dropdown');
    const deviceSearchInput    = document.getElementById('device-search-input');
    const proxyHostsWarning    = document.getElementById('proxy-hosts-warning');
    const warningDeviceMsg     = document.getElementById('warning-device-msg');
    const activeDeviceIcon     = document.getElementById('active-device-icon');
    const activeDeviceName     = document.getElementById('active-device-name');
    const activeDeviceIp       = document.getElementById('active-device-ip');
    const blCheckboxContainer  = document.getElementById('blocklist-checkboxes');
    const matrixTableBody      = document.getElementById('matrix-table-body');
    const matrixTableHead      = document.querySelector('#schedule-matrix-table thead');
    const rulesPreviewTextbox  = document.getElementById('rules-preview-textbox');
    const copyRulesBtn         = document.getElementById('copy-rules-btn');
    const applyPolicyBtn       = document.getElementById('apply-policy-btn');
    const saveStatusText       = document.getElementById('save-status-text');
    const presetBlockAll       = document.getElementById('preset-block-all');
    const presetAllowAll       = document.getElementById('preset-allow-all');
    const presetNight          = document.getElementById('preset-night');
    const presetSchool         = document.getElementById('preset-school');
    const presetWeekends       = document.getElementById('preset-weekends');

    const DAY_LETTERS = ['S', 'M', 'T', 'W', 'H', 'F', 'A'];

    // ──────────────────────────────────────────────────────────────
    // STATE
    // ──────────────────────────────────────────────────────────────
    let isAuthenticated  = false;
    let currentUser      = '';
    let devicesData      = [];
    let blocklistsData   = [];
    let devicePolicies   = {};
    let currentDeviceIp  = '';
    let adminDataLoaded  = false;

    // Drag state
    let isDragging       = false;
    let dragBlockValue   = true;   // true = block, false = allow

    // ──────────────────────────────────────────────────────────────
    // AUTH INIT
    // ──────────────────────────────────────────────────────────────
    checkAuthStatus();

    async function checkAuthStatus() {
        try {
            const res  = await fetch('/api/auth/status');
            const data = await res.json();
            isAuthenticated = !!data.authenticated;
            currentUser     = data.user || '';
        } catch (_) {
            isAuthenticated = false;
        }
        updateAuthUI();
        // If already authenticated (page refresh), auto-load admin data
        if (isAuthenticated && !adminDataLoaded) {
            loadAdminData();
        }
    }

    function updateAuthUI() {
        if (isAuthenticated) {
            userBadge && userBadge.classList.remove('hidden');
            currentUserSpan && (currentUserSpan.textContent = currentUser);
            authActionBtn && (authActionBtn.textContent = 'Logout');
        } else {
            userBadge && userBadge.classList.add('hidden');
            authActionBtn && (authActionBtn.textContent = 'Admin Login');
        }
    }

    // ──────────────────────────────────────────────────────────────
    // NAVIGATION
    // ──────────────────────────────────────────────────────────────
    navTabOnboarding && navTabOnboarding.addEventListener('click', () => {
        navTabOnboarding.classList.add('active');
        navTabAdmin.classList.remove('active');
        onboardingScreen.classList.remove('hidden');
        adminScreen.classList.add('hidden');
    });

    navTabAdmin && navTabAdmin.addEventListener('click', () => {
        if (!isAuthenticated) {
            authModal.classList.remove('hidden');
        } else {
            switchToAdmin();
        }
    });

    function switchToAdmin() {
        navTabAdmin.classList.add('active');
        navTabOnboarding.classList.remove('active');
        adminScreen.classList.remove('hidden');
        onboardingScreen.classList.add('hidden');
        if (!adminDataLoaded) {
            loadAdminData();
        }
    }

    // Platform tabs
    if (guideTabWindows && guideTabUbuntu) {
        guideTabWindows.addEventListener('click', () => {
            guideTabWindows.classList.add('active');
            guideTabUbuntu.classList.remove('active');
            guideContentWindows.classList.remove('hidden');
            guideContentUbuntu.classList.add('hidden');
        });
        guideTabUbuntu.addEventListener('click', () => {
            guideTabUbuntu.classList.add('active');
            guideTabWindows.classList.remove('active');
            guideContentUbuntu.classList.remove('hidden');
            guideContentWindows.classList.add('hidden');
        });
    }

    // ──────────────────────────────────────────────────────────────
    // AUTH MODAL
    // ──────────────────────────────────────────────────────────────
    authActionBtn && authActionBtn.addEventListener('click', () => {
        if (isAuthenticated) {
            fetch('/api/logout', { method: 'POST' }).finally(() => {
                isAuthenticated = false;
                currentUser     = '';
                adminDataLoaded = false;
                updateAuthUI();
                navTabOnboarding && navTabOnboarding.click();
            });
        } else {
            authModal.classList.remove('hidden');
        }
    });

    authModalClose && authModalClose.addEventListener('click', () => authModal.classList.add('hidden'));

    authModal && authModal.addEventListener('click', (e) => {
        if (e.target === authModal) authModal.classList.add('hidden');
    });

    loginForm && loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginError.classList.add('hidden');
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        try {
            const res  = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await res.json();
            if (res.ok && data.success) {
                isAuthenticated = true;
                currentUser     = username;
                updateAuthUI();
                authModal.classList.add('hidden');
                switchToAdmin();
            } else {
                loginError.textContent = data.error || 'Authentication failed.';
                loginError.classList.remove('hidden');
            }
        } catch (_) {
            loginError.textContent = 'Network error. Please try again.';
            loginError.classList.remove('hidden');
        }
    });

    // ──────────────────────────────────────────────────────────────
    // ADMIN DATA LOAD
    // ──────────────────────────────────────────────────────────────
    async function loadAdminData() {
        if (saveStatusText) saveStatusText.textContent = '⏳ Loading device data…';
        try {
            const [devRes, blRes, polRes] = await Promise.all([
                fetch('/api/devices'),
                fetch('/api/blocklists'),
                fetch('/api/policies')
            ]);

            if (devRes.status === 401 || blRes.status === 401) {
                if (saveStatusText) saveStatusText.textContent = '🔒 Not authenticated. Please log in.';
                return;
            }

            const devData = await devRes.json();
            const blData  = await blRes.json();
            const polData = await polRes.json();

            devicesData    = devData.devices   || [];
            blocklistsData = blData.blocklists || [];
            devicePolicies = polData.policies  || {};

            adminDataLoaded = true;

            buildScheduleMatrixGrid();   // build FIRST (empty table structure)
            renderTop5Buttons();
            renderDropdown();
            renderBlocklistCheckboxes();

            if (devicesData.length > 0) {
                selectDevice(devicesData[0].ip);
            } else {
                if (saveStatusText) saveStatusText.textContent = '⚠️ No active devices found in devices.list.';
            }
        } catch (err) {
            console.error('loadAdminData error:', err);
            if (saveStatusText) saveStatusText.textContent = '❌ Failed to load data from server.';
        }
    }

    // ──────────────────────────────────────────────────────────────
    // DEVICE ICON HELPER
    // ──────────────────────────────────────────────────────────────
    function getIcon(name) {
        const n = (name || '').toLowerCase();
        if (n.startsWith('phone'))  return '📱';
        if (n.startsWith('laptop')) return '💻';
        if (n.startsWith('pc'))     return '🖥️';
        if (n.startsWith('tablet')) return '📱';
        return '📟';
    }

    // ──────────────────────────────────────────────────────────────
    // TOP 5 QUICK BUTTONS
    // ──────────────────────────────────────────────────────────────
    function renderTop5Buttons() {
        if (!top5DevicesButtons) return;
        top5DevicesButtons.innerHTML = '';
        const top5 = devicesData.slice(0, 5);
        if (top5.length === 0) {
            top5DevicesButtons.innerHTML = '<span class="status-text" style="opacity:.6">No devices in devices.list</span>';
            return;
        }
        top5.forEach(dev => {
            const btn = document.createElement('button');
            btn.type      = 'button';
            btn.className = `top5-btn ${dev.ip === currentDeviceIp ? 'active' : ''}`;
            btn.innerHTML = `${getIcon(dev.name)} ${dev.name}`;
            btn.title     = `${dev.ip} — ${dev.hostname}`;
            btn.addEventListener('click', () => selectDevice(dev.ip));
            top5DevicesButtons.appendChild(btn);
        });
    }

    // ──────────────────────────────────────────────────────────────
    // DROPDOWN SELECTOR
    // ──────────────────────────────────────────────────────────────
    function renderDropdown() {
        if (!allDevicesDropdown) return;
        allDevicesDropdown.innerHTML = '<option value="">-- Select Device --</option>';
        devicesData.forEach(dev => {
            const opt   = document.createElement('option');
            opt.value   = dev.ip;
            opt.textContent = `${dev.name}  (${dev.ip})`;
            allDevicesDropdown.appendChild(opt);
        });
        allDevicesDropdown.value = currentDeviceIp;
    }

    allDevicesDropdown && allDevicesDropdown.addEventListener('change', (e) => {
        if (e.target.value) selectDevice(e.target.value);
    });

    deviceSearchInput && deviceSearchInput.addEventListener('input', (e) => {
        const q = e.target.value.toLowerCase().trim();
        // Filter the dropdown options to match search
        if (allDevicesDropdown) {
            Array.from(allDevicesDropdown.options).forEach(opt => {
                if (!opt.value) return;
                opt.hidden = q && !opt.textContent.toLowerCase().includes(q);
            });
        }
    });

    // ──────────────────────────────────────────────────────────────
    // DEVICE SELECTION
    // ──────────────────────────────────────────────────────────────
    function selectDevice(ip) {
        if (!ip) return;
        currentDeviceIp = ip;

        // Sync all selector UI
        renderTop5Buttons();
        renderDropdown();

        const dev = devicesData.find(d => d.ip === ip) || { ip, hostname: ip, name: ip };

        // Update status bar
        if (activeDeviceIcon) activeDeviceIcon.textContent = getIcon(dev.name);
        if (activeDeviceName) activeDeviceName.textContent = `${dev.name}  (${dev.hostname})`;
        if (activeDeviceIp)   activeDeviceIp.textContent   = `IP: ${dev.ip}`;

        // Proxy-hosts warning
        if (dev.in_proxy_hosts === false) {
            if (warningDeviceMsg) warningDeviceMsg.textContent =
                `⚠️  '${dev.name}' (${dev.ip}) is NOT in router/proxy-hosts.conf — blocking rules won't work on the router until it is added!`;
            if (proxyHostsWarning) proxyHostsWarning.classList.remove('hidden');
        } else {
            if (proxyHostsWarning) proxyHostsWarning.classList.add('hidden');
        }

        // Load or init policy
        const policy = ensurePolicy(ip);
        syncCheckboxes(policy.blocklists);
        syncMatrixUI(policy.matrix);
        updateRulesPreview();

        if (saveStatusText) saveStatusText.textContent = `Editing: ${dev.name} (${dev.ip}) — click Apply to push to Squid.`;
    }

    // ──────────────────────────────────────────────────────────────
    // POLICY HELPERS
    // ──────────────────────────────────────────────────────────────
    function ensurePolicy(ip) {
        if (!devicePolicies[ip]) {
            const dev = devicesData.find(d => d.ip === ip) || { ip, hostname: ip, name: ip };
            devicePolicies[ip] = {
                ip:         dev.ip,
                hostname:   dev.hostname,
                blocklists: [],
                matrix:     Array.from({ length: 7 }, () => Array(48).fill(false))
            };
        }
        return devicePolicies[ip];
    }

    // ──────────────────────────────────────────────────────────────
    // BLOCKLIST CHECKBOXES
    // ──────────────────────────────────────────────────────────────
    function renderBlocklistCheckboxes() {
        if (!blCheckboxContainer) return;
        blCheckboxContainer.innerHTML = '';
        blocklistsData.forEach(bl => {
            const label = document.createElement('label');
            label.className = 'blocklist-chip';
            label.title     = bl;
            label.innerHTML = `
                <input type="checkbox" value="${bl}">
                <span class="bl-name">🛡️ ${bl}</span>`;
            const chk = label.querySelector('input');
            chk.addEventListener('change', () => {
                if (!currentDeviceIp) return;
                const pol = ensurePolicy(currentDeviceIp);
                if (chk.checked) {
                    if (!pol.blocklists.includes(bl)) pol.blocklists.push(bl);
                } else {
                    pol.blocklists = pol.blocklists.filter(x => x !== bl);
                }
                updateRulesPreview();
                scheduleAutoSave();
            });
            blCheckboxContainer.appendChild(label);
        });
    }

    function syncCheckboxes(selectedList) {
        if (!blCheckboxContainer) return;
        blCheckboxContainer.querySelectorAll('input[type="checkbox"]').forEach(chk => {
            chk.checked = selectedList.includes(chk.value);
        });
    }

    // ──────────────────────────────────────────────────────────────
    // SCHEDULE MATRIX
    // ──────────────────────────────────────────────────────────────
    function slotLabel(s) {
        const h0 = Math.floor(s / 2), m0 = (s % 2) * 30;
        const h1 = m0 === 30 ? h0 + 1 : h0, m1 = m0 === 30 ? 0 : 30;
        return `${pad(h0)}:${pad(m0)} - ${pad(h1)}:${pad(m1)}`;
    }
    function slotStart(s) { return `${pad(Math.floor(s/2))}:${pad((s%2)*30)}`; }
    function slotEnd(s)   { return s >= 47 ? '23:59' : slotStart(s + 1); }
    function pad(n)       { return String(n).padStart(2, '0'); }

    function buildScheduleMatrixGrid() {
        if (!matrixTableBody) return;
        matrixTableBody.innerHTML = '';

        for (let s = 0; s < 48; s++) {
            const tr = document.createElement('tr');

            // Time slot label — clicking toggles entire row
            const tdHdr = document.createElement('td');
            tdHdr.className        = 'slot-header';
            tdHdr.textContent      = slotLabel(s);
            tdHdr.dataset.slot     = s;
            tdHdr.title            = 'Click to toggle entire row';
            tdHdr.addEventListener('click', () => { toggleRow(s); updateRulesPreview(); scheduleAutoSave(); });
            tr.appendChild(tdHdr);

            // 7 day cells
            for (let d = 0; d < 7; d++) {
                const td = document.createElement('td');
                td.className    = 'matrix-cell';
                td.dataset.day  = d;
                td.dataset.slot = s;

                td.addEventListener('mousedown', (e) => {
                    if (e.button !== 0) return;         // left-click only
                    e.preventDefault();
                    if (!currentDeviceIp) return;
                    isDragging     = true;
                    const pol      = ensurePolicy(currentDeviceIp);
                    dragBlockValue = !pol.matrix[d][s]; // toggle based on current state
                    applyCell(d, s, dragBlockValue);
                    updateRulesPreview();
                    scheduleAutoSave();
                });

                td.addEventListener('mouseenter', () => {
                    if (isDragging && currentDeviceIp) {
                        applyCell(d, s, dragBlockValue);
                        updateRulesPreview();
                        scheduleAutoSave();
                    }
                });

                tr.appendChild(td);
            }
            matrixTableBody.appendChild(tr);
        }

        // Day header clicks to toggle columns
        if (matrixTableHead) {
            matrixTableHead.querySelectorAll('th.day-col').forEach(th => {
                th.addEventListener('click', () => {
                    const d = parseInt(th.dataset.day, 10);
                    toggleColumn(d);
                    updateRulesPreview();
                    scheduleAutoSave();
                });
            });
        }
    }

    // Stop drag on mouse release — must be document-level
    document.addEventListener('mouseup', () => { isDragging = false; });
    // Prevent text selection during drag inside the table
    document.addEventListener('dragstart', (e) => { if (isDragging) e.preventDefault(); });

    function applyCell(day, slot, blocked) {
        if (!currentDeviceIp) return;
        ensurePolicy(currentDeviceIp).matrix[day][slot] = blocked;
        const cell = matrixTableBody.querySelector(`td[data-day="${day}"][data-slot="${slot}"]`);
        if (!cell) return;
        if (blocked) {
            cell.classList.add('blocked');
            cell.textContent = '🚫';
        } else {
            cell.classList.remove('blocked');
            cell.textContent = '';
        }
    }

    function syncMatrixUI(matrix) {
        if (!matrixTableBody) return;
        for (let d = 0; d < 7; d++) {
            for (let s = 0; s < 48; s++) {
                applyCell(d, s, !!(matrix[d] && matrix[d][s]));
            }
        }
    }

    function toggleRow(slot) {
        if (!currentDeviceIp) return;
        const pol = ensurePolicy(currentDeviceIp);
        const allBlocked = DAY_LETTERS.every((_, d) => pol.matrix[d][slot]);
        for (let d = 0; d < 7; d++) applyCell(d, slot, !allBlocked);
    }

    function toggleColumn(day) {
        if (!currentDeviceIp) return;
        const pol = ensurePolicy(currentDeviceIp);
        const allBlocked = pol.matrix[day].every(v => v);
        for (let s = 0; s < 48; s++) applyCell(day, s, !allBlocked);
    }

    // ──────────────────────────────────────────────────────────────
    // PRESETS
    // ──────────────────────────────────────────────────────────────
    presetBlockAll  && presetBlockAll.addEventListener('click', () => {
        if (!currentDeviceIp) return;
        for (let d = 0; d < 7; d++) for (let s = 0; s < 48; s++) applyCell(d, s, true);
        updateRulesPreview(); scheduleAutoSave();
    });
    presetAllowAll  && presetAllowAll.addEventListener('click', () => {
        if (!currentDeviceIp) return;
        for (let d = 0; d < 7; d++) for (let s = 0; s < 48; s++) applyCell(d, s, false);
        updateRulesPreview(); scheduleAutoSave();
    });
    presetNight     && presetNight.addEventListener('click', () => {
        if (!currentDeviceIp) return;
        for (let d = 0; d < 7; d++)
            for (let s = 0; s < 48; s++)
                if (s >= 44 || s < 14) applyCell(d, s, true);
        updateRulesPreview(); scheduleAutoSave();
    });
    presetSchool    && presetSchool.addEventListener('click', () => {
        if (!currentDeviceIp) return;
        for (let d = 1; d <= 5; d++)
            for (let s = 16; s < 32; s++)
                applyCell(d, s, true);
        updateRulesPreview(); scheduleAutoSave();
    });
    presetWeekends  && presetWeekends.addEventListener('click', () => {
        if (!currentDeviceIp) return;
        [0, 6].forEach(d => { for (let s = 0; s < 48; s++) applyCell(d, s, true); });
        updateRulesPreview(); scheduleAutoSave();
    });

    // ──────────────────────────────────────────────────────────────
    // AUTO-SAVE POLICIES (silent debounced background save)
    // ──────────────────────────────────────────────────────────────
    let autoSaveTimer = null;
    function scheduleAutoSave() {
        clearTimeout(autoSaveTimer);
        autoSaveTimer = setTimeout(async () => {
            try {
                await fetch('/api/policies', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ policies: devicePolicies })
                });
                if (saveStatusText) saveStatusText.textContent = '💾 Auto-saved.';
            } catch (_) { /* silent */ }
        }, 800);
    }

    // ──────────────────────────────────────────────────────────────
    // REAL-TIME RULES PREVIEW
    // ──────────────────────────────────────────────────────────────
    function updateRulesPreview() {
        if (!rulesPreviewTextbox) return;

        const pol = devicePolicies[currentDeviceIp];
        const dev = devicesData.find(d => d.ip === currentDeviceIp);

        if (!pol || !dev) {
            rulesPreviewTextbox.value = '# Select a device to see generated rules.';
            return;
        }

        const lines = [
            `# ${'='.repeat(60)}`,
            `# SQUID ACL RULES — Device: ${dev.name} (${dev.ip})`,
            `# Generated: ${new Date().toLocaleString()}`,
            `# ${'='.repeat(60)}`,
            ''
        ];

        if (!pol.blocklists || pol.blocklists.length === 0) {
            lines.push('# No blocklists selected — all traffic allowed.');
            rulesPreviewTextbox.value = lines.join('\n');
            return;
        }

        const cleanIp = dev.ip.replace(/\./g, '_');
        const srcAcl  = `src_dev_${cleanIp}`;
        lines.push(`acl ${srcAcl} src ${dev.ip}`);

        pol.blocklists.forEach(bl => {
            const blAcl = `list_${bl.replace(/[.\-]/g, '_')}`;
            lines.push(`acl ${blAcl} dstdomain "/etc/squid/block-lists/${bl}"`);
        });
        lines.push('');

        // Build time ranges grouped by day
        const matrix = pol.matrix;
        const rangeToDays = {};

        for (let d = 0; d < 7; d++) {
            const daySlots = matrix[d] || Array(48).fill(false);
            let inRange = false, startSlot = 0;
            for (let s = 0; s < 48; s++) {
                if (daySlots[s] && !inRange) {
                    inRange = true; startSlot = s;
                } else if (!daySlots[s] && inRange) {
                    inRange = false;
                    const key = `${slotStart(startSlot)}-${slotEnd(s - 1)}`;
                    if (!rangeToDays[key]) rangeToDays[key] = [];
                    rangeToDays[key].push(DAY_LETTERS[d]);
                }
            }
            if (inRange) {
                const key = `${slotStart(startSlot)}-${slotEnd(47)}`;
                if (!rangeToDays[key]) rangeToDays[key] = [];
                rangeToDays[key].push(DAY_LETTERS[d]);
            }
        }

        if (Object.keys(rangeToDays).length === 0) {
            lines.push('# No blocked time slots — all traffic allowed.');
            rulesPreviewTextbox.value = lines.join('\n');
            return;
        }

        let idx = 0;
        Object.entries(rangeToDays).forEach(([timeRange, days]) => {
            const timeAcl = `time_dev_${cleanIp}_${idx++}`;
            lines.push(`acl ${timeAcl} time ${days.join('')} ${timeRange}`);
            pol.blocklists.forEach(bl => {
                const blAcl = `list_${bl.replace(/[.\-]/g, '_')}`;
                lines.push(`http_access deny ${srcAcl} ${blAcl} ${timeAcl}`);
            });
        });

        rulesPreviewTextbox.value = lines.join('\n');
    }

    copyRulesBtn && copyRulesBtn.addEventListener('click', () => {
        if (!rulesPreviewTextbox || !rulesPreviewTextbox.value) return;
        navigator.clipboard.writeText(rulesPreviewTextbox.value).then(() => {
            const orig = copyRulesBtn.textContent;
            copyRulesBtn.textContent = '✅ Copied!';
            setTimeout(() => { copyRulesBtn.textContent = orig; }, 2000);
        });
    });

    // ──────────────────────────────────────────────────────────────
    // APPLY BUTTON
    // ──────────────────────────────────────────────────────────────
    applyPolicyBtn && applyPolicyBtn.addEventListener('click', async () => {
        if (!isAuthenticated) {
            authModal.classList.remove('hidden');
            return;
        }
        applyPolicyBtn.disabled = true;
        saveStatusText.textContent = '⏳ Saving & compiling Squid ACLs…';
        try {
            const saveRes = await fetch('/api/policies', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ policies: devicePolicies })
            });
            if (!saveRes.ok) throw new Error('Save failed');

            const applyRes  = await fetch('/api/apply', { method: 'POST' });
            const applyData = await applyRes.json();

            saveStatusText.textContent = applyRes.ok && applyData.success
                ? '✅ Policies applied — Squid reloaded successfully!'
                : `❌ Apply failed: ${applyData.message || 'Unknown error'}`;
        } catch (err) {
            saveStatusText.textContent = `❌ Error: ${err.message}`;
        } finally {
            applyPolicyBtn.disabled = false;
        }
    });

});
