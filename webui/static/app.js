/**
 * Squid Web UI — app.js v3
 * 3-category model: always_block + always_allow + automatic default_block.
 * Schedule mode: Basic (all default_block lists share one matrix) / Advanced (per-list).
 * Timetable: drag = ALLOW (green). Empty = blocked by default.
 * Dual mode: Weekly (7×48) and Today (1×48).
 */
document.addEventListener('DOMContentLoaded', () => {

    // ─────────────────────────────────────────────────────────────
    // DOM REFERENCES
    // ─────────────────────────────────────────────────────────────
    const navTabOnboarding    = document.getElementById('nav-tab-onboarding');
    const navTabAdmin         = document.getElementById('nav-tab-admin');
    const navTabActivity      = document.getElementById('nav-tab-activity');
    const onboardingScreen    = document.getElementById('onboarding-screen');
    const adminScreen         = document.getElementById('admin-screen');
    const activityScreen      = document.getElementById('activity-screen');
    const userBadge           = document.getElementById('user-badge');
    const currentUserSpan     = document.getElementById('current-user');
    const authActionBtn       = document.getElementById('auth-action-btn');
    const guideTabWindows     = document.getElementById('guide-tab-windows');
    const guideTabUbuntu      = document.getElementById('guide-tab-ubuntu');
    const guideContentWindows = document.getElementById('guide-content-windows');
    const guideContentUbuntu  = document.getElementById('guide-content-ubuntu');
    const authModal           = document.getElementById('auth-modal');
    const authModalClose      = document.getElementById('auth-modal-close');
    const loginForm           = document.getElementById('login-form');
    const loginError          = document.getElementById('login-error');
    const adminRequested      = !!window.WEBUI_CONTEXT?.adminRequested;

    const top7DevicesButtons  = document.getElementById('top7-devices-buttons');
    const allDevicesDropdown  = document.getElementById('all-devices-dropdown');
    const deviceSearchInput   = document.getElementById('device-search-input');
    const proxyHostsWarning   = document.getElementById('proxy-hosts-warning');
    const warningDeviceMsg    = document.getElementById('warning-device-msg');
    const saveStatusText      = document.getElementById('save-status-text');
    const applyPolicyBtn      = document.getElementById('apply-policy-btn');
    const copyRulesBtn        = document.getElementById('copy-rules-btn');
    const rulesPreviewTextbox = document.getElementById('rules-preview-textbox');

    // Website activity
    const activityClientSelect  = document.getElementById('activity-client-select');
    const activityDateInput     = document.getElementById('activity-date-input');
    const activityRefreshBtn    = document.getElementById('activity-refresh-btn');
    const activityCategoryFilter = document.getElementById('activity-category-filter');
    const activitySearchInput   = document.getElementById('activity-search-input');
    const activityTableBody     = document.getElementById('activity-table-body');
    const activityEmptyState    = document.getElementById('activity-empty-state');
    const activityError         = document.getElementById('activity-error');
    const activityEstimateNote  = document.getElementById('activity-estimate-note');
    const activityTotalTime     = document.getElementById('activity-total-time');
    const activitySiteCount     = document.getElementById('activity-site-count');
    const activityRequestCount  = document.getElementById('activity-request-count');
    const activityBlockedCount  = document.getElementById('activity-blocked-count');

    // Section 1: Always Block
    const alwaysBlockCheckboxes  = document.getElementById('always-block-checkboxes');

    // Section 2: Always Allow
    const alwaysAllowCheckboxes  = document.getElementById('always-allow-checkboxes');

    // Section 3: Automatic Default Block
    const defaultBlockLists      = document.getElementById('default-block-lists');
    const dbListTabsContainer    = document.getElementById('db-list-tabs-container');
    const dbListTabs             = document.getElementById('db-list-tabs');
    const dbEmptyState           = document.getElementById('db-empty-state');

    // Basic/Advanced toggle
    const modeBasicBtn           = document.getElementById('sched-mode-basic-btn');
    const modeAdvancedBtn        = document.getElementById('sched-mode-advanced-btn');
    const advancedMultiNote      = document.getElementById('advanced-multi-note');

    // Weekly / Today mode
    const modeWeeklyBtn          = document.getElementById('mode-weekly-btn');
    const modeTodayBtn           = document.getElementById('mode-today-btn');
    const todayModeHint          = document.getElementById('today-mode-hint');
    const matrixTitle            = document.getElementById('matrix-title');
    const matrixSubtitle         = document.getElementById('matrix-subtitle');
    const weeklyTableWrap        = document.getElementById('weekly-table-wrap');
    const todayTableWrap         = document.getElementById('today-table-wrap');
    const matrixTableBody        = document.getElementById('matrix-table-body');
    const matrixTableHead        = document.querySelector('#schedule-matrix-table thead');
    const todayTableBody         = document.getElementById('today-table-body');
    const todayColHeader         = document.getElementById('today-col-header');

    // Presets
    const presetAllowAll  = document.getElementById('preset-allow-all');
    const presetBlockAll  = document.getElementById('preset-block-all');
    const presetNext30m   = document.getElementById('preset-next-30m');
    const presetNext1h    = document.getElementById('preset-next-1h');
    const presetNext2h    = document.getElementById('preset-next-2h');

    // ─────────────────────────────────────────────────────────────
    // STATE
    // ─────────────────────────────────────────────────────────────
    const DAY_LETTERS = ['S', 'M', 'T', 'W', 'H', 'F', 'A'];

    let isAuthenticated  = false;
    let isAdminClient    = false;
    let currentUser      = '';
    let devicesData      = [];
    let blocklistsData   = [];   // raw filenames e.g. ["gaming.txt", ...]
    let devicePolicies   = {};
    let currentDeviceIp  = '';
    let adminDataLoaded  = false;
    let activityData     = null;
    let activityClientsLoaded = false;
    let requestedProtectedView = 'admin';

    // Schedule UI state
    let scheduleMode     = 'today';   // 'weekly' | 'today'
    let schedEditMode    = 'basic';    // 'basic' | 'advanced'
    let activeListNames  = [];         // in advanced mode: which lists are selected for editing

    // Drag state
    let isDragging       = false;
    let dragAllowValue   = true;

    // ─────────────────────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────────────────────
    const pad = n => String(n).padStart(2, '0');

    function slotLabel(s) {
        const h0 = Math.floor(s / 2), m0 = (s % 2) * 30;
        const h1 = m0 === 30 ? h0 + 1 : h0, m1 = m0 === 30 ? 0 : 30;
        return `${pad(h0)}:${pad(m0)} – ${pad(h1)}:${pad(m1)}`;
    }
    const slotStart = s => `${pad(Math.floor(s / 2))}:${pad((s % 2) * 30)}`;
    const slotEnd   = s => s >= 47 ? '23:59' : slotStart(s + 1);

    /** Strip .txt from display names */
    const displayName = bl => bl.replace(/\.txt$/i, '');

    const escapeHtml = value => String(value).replace(/[&<>"']/g, char => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
    })[char]);

    function formatDuration(totalSeconds) {
        const seconds = Math.max(0, Math.round(totalSeconds || 0));
        if (seconds < 60) return `${seconds}s`;
        const minutes = Math.round(seconds / 60);
        if (minutes < 60) return `${minutes}m`;
        const hours = Math.floor(minutes / 60);
        return `${hours}h ${minutes % 60}m`;
    }

    const formatCategory = value => value.replaceAll('_', ' ').replace(/\b\w/g, char => char.toUpperCase());

    function getIcon(name) {
        const n = (name || '').toLowerCase();
        if (n.startsWith('phone'))  return '📱';
        if (n.startsWith('laptop')) return '💻';
        if (n.startsWith('pc'))     return '🖥️';
        if (n.startsWith('tablet')) return '📱';
        return '📟';
    }

    function todayDisplayName() {
        return ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'][new Date().getDay()];
    }

    // ─────────────────────────────────────────────────────────────
    // POLICY SCHEMA HELPERS
    // ─────────────────────────────────────────────────────────────
    const makeEmptyWeekly = () => Array.from({ length: 7 }, () => Array(48).fill(false));
    const makeEmptyToday  = () => Array(48).fill(false);
    const localToday = () => {
        const d = new Date();
        return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    };

    function ensurePolicy(ip) {
        if (!devicePolicies[ip]) {
            const dev = devicesData.find(d => d.ip === ip) || { ip, hostname: ip };
            devicePolicies[ip] = { ip, hostname: dev.hostname, always_block: [], always_allow: [], default_block: [] };
        }
        const pol = devicePolicies[ip];
        pol.always_block  = pol.always_block  || [];
        pol.always_allow  = pol.always_allow  || [];
        pol.default_block = pol.default_block || [];
        // Always Block wins malformed conflicts. Everything else is Default Block.
        pol.always_block = [...new Set(pol.always_block)];
        pol.always_allow = [...new Set(pol.always_allow)].filter(bl => !pol.always_block.includes(bl));
        reconcileDefaultBlock(pol);
        return pol;
    }

    function reconcileDefaultBlock(pol) {
        const explicit = new Set([...(pol.always_block || []), ...(pol.always_allow || [])]);
        const existing = new Map((pol.default_block || []).map(entry => [entry.list, entry]));
        // Before blocklist metadata loads, retain existing scheduled entries.
        const names = blocklistsData.length ? blocklistsData : [...existing.keys()];
        pol.default_block = names
            .filter(name => !explicit.has(name))
            .map(name => existing.get(name) || {
                list: name,
                unblock_weekly: makeEmptyWeekly(),
                unblock_today: makeEmptyToday(),
                today_date: localToday()
            });
    }

    function getOrCreateDbEntry(pol, listName) {
        let entry = pol.default_block.find(e => e.list === listName);
        if (!entry) {
            entry = { list: listName, unblock_weekly: makeEmptyWeekly(), unblock_today: makeEmptyToday(), today_date: localToday() };
            pol.default_block.push(entry);
        }
        entry.unblock_weekly = entry.unblock_weekly || makeEmptyWeekly();
        entry.unblock_today  = entry.unblock_today  || makeEmptyToday();
        return entry;
    }

    /** Return the list of listNames that are currently targeted for editing */
    function editingLists() {
        if (!currentDeviceIp) return [];
        const pol = ensurePolicy(currentDeviceIp);
        const dbLists = pol.default_block.map(e => e.list);
        if (schedEditMode === 'basic') {
            return dbLists;  // all of them
        }
        // advanced: the currently selected subset
        return activeListNames.filter(n => dbLists.includes(n));
    }

    // ─────────────────────────────────────────────────────────────
    // AUTH INIT
    // ─────────────────────────────────────────────────────────────
    checkAuthStatus();

    async function checkAuthStatus() {
        try {
            const res  = await fetch('/api/auth/status');
            const data = await res.json();
            isAuthenticated = !!data.authenticated;
            isAdminClient   = !!data.is_admin_client;
            currentUser     = data.user || '';
        } catch (_) {
            isAuthenticated = false;
            isAdminClient = false;
        }
        updateAuthUI();

        // The admin DOM is deliberately absent on / for non-admin clients.
        if (!navTabAdmin || !adminScreen) return;

        if (isAuthenticated && (isAdminClient || adminRequested)) {
            switchToAdmin();
        } else if (adminRequested) {
            authModal && authModal.classList.remove('hidden');
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
        // An allowlisted client cannot meaningfully log out: its IP remains
        // trusted, so avoid presenting a misleading Logout action.
        authActionBtn && authActionBtn.classList.toggle('hidden', isAdminClient);
    }

    // ─────────────────────────────────────────────────────────────
    // NAVIGATION
    // ─────────────────────────────────────────────────────────────
    navTabOnboarding && navTabOnboarding.addEventListener('click', () => {
        navTabOnboarding.classList.add('active');
        navTabAdmin && navTabAdmin.classList.remove('active');
        navTabActivity && navTabActivity.classList.remove('active');
        onboardingScreen && onboardingScreen.classList.remove('hidden');
        adminScreen && adminScreen.classList.add('hidden');
        activityScreen && activityScreen.classList.add('hidden');
    });
    navTabAdmin && navTabAdmin.addEventListener('click', () => {
        requestedProtectedView = 'admin';
        if (!isAuthenticated) { authModal.classList.remove('hidden'); }
        else { switchToAdmin(); }
    });
    navTabActivity && navTabActivity.addEventListener('click', () => {
        requestedProtectedView = 'activity';
        if (!isAuthenticated) { authModal.classList.remove('hidden'); }
        else { switchToActivity(); }
    });

    function switchToAdmin() {
        navTabAdmin && navTabAdmin.classList.add('active');
        navTabOnboarding && navTabOnboarding.classList.remove('active');
        navTabActivity && navTabActivity.classList.remove('active');
        adminScreen && adminScreen.classList.remove('hidden');
        onboardingScreen && onboardingScreen.classList.add('hidden');
        activityScreen && activityScreen.classList.add('hidden');
        if (!adminDataLoaded) loadAdminData();
    }

    function switchToActivity() {
        navTabActivity && navTabActivity.classList.add('active');
        navTabAdmin && navTabAdmin.classList.remove('active');
        navTabOnboarding && navTabOnboarding.classList.remove('active');
        activityScreen && activityScreen.classList.remove('hidden');
        adminScreen && adminScreen.classList.add('hidden');
        onboardingScreen && onboardingScreen.classList.add('hidden');
        if (activityDateInput && !activityDateInput.value) {
            activityDateInput.value = localToday();
            activityDateInput.max = localToday();
        }
        loadActivityClients();
    }

    async function loadActivityClients() {
        if (!activityClientSelect) return;
        if (!activityClientsLoaded) {
            try {
                if (!devicesData.length) {
                    const response = await fetch('/api/devices');
                    if (!response.ok) throw new Error('Could not load clients.');
                    devicesData = (await response.json()).devices || [];
                }
                const previous = activityClientSelect.value;
                activityClientSelect.innerHTML = '<option value="">-- Select Client --</option>';
                devicesData.forEach(device => {
                    const option = document.createElement('option');
                    option.value = device.ip;
                    option.textContent = `${device.hostname || device.ip} (${device.ip})`;
                    activityClientSelect.appendChild(option);
                });
                activityClientSelect.value = previous || currentDeviceIp || devicesData[0]?.ip || '';
                activityClientsLoaded = true;
            } catch (error) {
                showActivityError(error.message);
                return;
            }
        }
        if (activityClientSelect.value) loadActivity();
    }

    async function loadActivity() {
        const clientIp = activityClientSelect?.value;
        const targetDate = activityDateInput?.value;
        if (!clientIp || !targetDate) return;

        showActivityError('');
        activityRefreshBtn && (activityRefreshBtn.disabled = true);
        activityEstimateNote && (activityEstimateNote.textContent = 'Analyzing Squid access logs…');
        try {
            const params = new URLSearchParams({ client_ip: clientIp, date: targetDate });
            const response = await fetch(`/api/activity?${params}`);
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'Could not load website activity.');
            activityData = data;
            populateActivityCategories();
            renderActivity();
        } catch (error) {
            activityData = null;
            showActivityError(error.message);
            renderActivity();
        } finally {
            activityRefreshBtn && (activityRefreshBtn.disabled = false);
        }
    }

    function showActivityError(message) {
        if (!activityError) return;
        activityError.textContent = message;
        activityError.classList.toggle('hidden', !message);
    }

    function populateActivityCategories() {
        if (!activityCategoryFilter) return;
        const selected = activityCategoryFilter.value;
        const categories = [...new Set((activityData?.sites || []).flatMap(site => site.categories))].sort();
        activityCategoryFilter.innerHTML = '<option value="">All categories</option>';
        categories.forEach(category => {
            const option = document.createElement('option');
            option.value = category;
            option.textContent = formatCategory(category);
            activityCategoryFilter.appendChild(option);
        });
        if (categories.includes(selected)) activityCategoryFilter.value = selected;
    }

    function renderActivity() {
        const sites = activityData?.sites || [];
        const category = activityCategoryFilter?.value || '';
        const search = (activitySearchInput?.value || '').trim().toLowerCase();
        const filtered = sites.filter(site =>
            (!category || site.categories.includes(category)) &&
            (!search || site.site.toLowerCase().includes(search))
        );

        activityTotalTime && (activityTotalTime.textContent = activityData ? formatDuration(activityData.estimated_seconds) : '—');
        activitySiteCount && (activitySiteCount.textContent = activityData ? activityData.unique_sites.toLocaleString() : '—');
        activityRequestCount && (activityRequestCount.textContent = activityData ? activityData.requests.toLocaleString() : '—');
        activityBlockedCount && (activityBlockedCount.textContent = activityData ? activityData.blocked_requests.toLocaleString() : '—');
        if (activityEstimateNote) {
            activityEstimateNote.textContent = activityData
                ? `${activityData.estimation.description} Background traffic may be included.`
                : 'Choose a client to load its activity.';
        }

        if (activityTableBody) {
            activityTableBody.innerHTML = filtered.map(site => {
                const categories = site.categories.map(value =>
                    `<span class="activity-category-tag ${value === 'uncategorized' ? 'muted' : ''}">${escapeHtml(formatCategory(value))}</span>`
                ).join('');
                const lastSeen = new Date(site.last_seen_epoch * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                return `<tr>
                    <td class="activity-site-cell">${escapeHtml(site.site)}</td>
                    <td><div class="activity-category-list">${categories}</div></td>
                    <td><strong>${formatDuration(site.estimated_seconds)}</strong></td>
                    <td>${site.requests.toLocaleString()}</td>
                    <td class="${site.blocked_requests ? 'activity-blocked-value' : ''}">${site.blocked_requests.toLocaleString()}</td>
                    <td>${escapeHtml(lastSeen)}</td>
                </tr>`;
            }).join('');
        }
        activityEmptyState && activityEmptyState.classList.toggle('hidden', filtered.length > 0);
        const table = activityTableBody?.closest('table');
        table && table.classList.toggle('hidden', filtered.length === 0);
        const emptyTitle = activityEmptyState?.querySelector('h3');
        const emptyText = activityEmptyState?.querySelector('p');
        if (activityData && !filtered.length) {
            emptyTitle && (emptyTitle.textContent = sites.length ? 'No matching websites' : 'No website activity found');
            emptyText && (emptyText.textContent = sites.length ? 'Try changing the category or search filter.' : 'Squid recorded no website requests for this client and date.');
        }
    }

    activityClientSelect && activityClientSelect.addEventListener('change', loadActivity);
    activityDateInput && activityDateInput.addEventListener('change', loadActivity);
    activityRefreshBtn && activityRefreshBtn.addEventListener('click', loadActivity);
    activityCategoryFilter && activityCategoryFilter.addEventListener('change', renderActivity);
    activitySearchInput && activitySearchInput.addEventListener('input', renderActivity);

    if (guideTabWindows && guideTabUbuntu) {
        guideTabWindows.addEventListener('click', () => {
            guideTabWindows.classList.add('active'); guideTabUbuntu.classList.remove('active');
            guideContentWindows.classList.remove('hidden'); guideContentUbuntu.classList.add('hidden');
        });
        guideTabUbuntu.addEventListener('click', () => {
            guideTabUbuntu.classList.add('active'); guideTabWindows.classList.remove('active');
            guideContentUbuntu.classList.remove('hidden'); guideContentWindows.classList.add('hidden');
        });
    }

    // ─────────────────────────────────────────────────────────────
    // AUTH MODAL
    // ─────────────────────────────────────────────────────────────
    authActionBtn && authActionBtn.addEventListener('click', () => {
        if (isAuthenticated) {
            fetch('/api/logout', { method: 'POST' }).finally(() => {
                isAuthenticated = false; currentUser = ''; adminDataLoaded = false;
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
                isAuthenticated = true; currentUser = username;
                updateAuthUI(); authModal.classList.add('hidden');
                if (requestedProtectedView === 'activity') switchToActivity();
                else switchToAdmin();
            } else {
                loginError.textContent = data.error || 'Authentication failed.';
                loginError.classList.remove('hidden');
            }
        } catch (_) {
            loginError.textContent = 'Network error. Please try again.';
            loginError.classList.remove('hidden');
        }
    });

    // ─────────────────────────────────────────────────────────────
    // ADMIN DATA LOAD
    // ─────────────────────────────────────────────────────────────
    async function loadAdminData() {
        if (saveStatusText) saveStatusText.textContent = '⏳ Loading device data…';
        try {
            const [devRes, blRes, polRes] = await Promise.all([
                fetch('/api/devices'),
                fetch('/api/blocklists'),
                fetch('/api/policies')
            ]);
            if (devRes.status === 401) {
                if (saveStatusText) saveStatusText.textContent = '🔒 Not authenticated. Please log in.';
                return;
            }
            devicesData    = (await devRes.json()).devices   || [];
            blocklistsData = (await blRes.json()).blocklists || [];
            devicePolicies = (await polRes.json()).policies  || {};

            adminDataLoaded = true;

            buildWeeklyGrid();
            buildTodayGrid();
            renderTop7Buttons();
            renderDropdown();
            renderAllBlocklistCheckboxes();

            if (devicesData.length > 0) selectDevice(devicesData[0].ip);
            else if (saveStatusText) saveStatusText.textContent = '⚠️ No active devices found.';

            // Auto-scroll the matrix to the current time
            setTimeout(scrollToCurrentTime, 100);
        } catch (err) {
            console.error('loadAdminData error:', err);
            if (saveStatusText) saveStatusText.textContent = '❌ Failed to load data from server.';
        }
    }

    // ─────────────────────────────────────────────────────────────
    // TOP 7 / DROPDOWN
    // ─────────────────────────────────────────────────────────────
    function renderTop7Buttons() {
        if (!top7DevicesButtons) return;
        top7DevicesButtons.innerHTML = '';
        devicesData.slice(0, 7).forEach(dev => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = `top7-btn ${dev.ip === currentDeviceIp ? 'active' : ''}`;
            btn.innerHTML = `${getIcon(dev.name)} ${dev.name}`;
            btn.title = `${dev.ip} — ${dev.hostname}`;
            btn.addEventListener('click', () => selectDevice(dev.ip));
            top7DevicesButtons.appendChild(btn);
        });
    }

    function renderDropdown() {
        if (!allDevicesDropdown) return;
        allDevicesDropdown.innerHTML = '<option value="">-- Select Device --</option>';
        devicesData.forEach(dev => {
            const opt = document.createElement('option');
            opt.value = dev.ip;
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
        Array.from(allDevicesDropdown.options).forEach(opt => {
            if (!opt.value) return;
            opt.hidden = q && !opt.textContent.toLowerCase().includes(q);
        });
    });

    // ─────────────────────────────────────────────────────────────
    // DEVICE SELECTION
    // ─────────────────────────────────────────────────────────────
    function selectDevice(ip) {
        if (!ip) return;
        currentDeviceIp = ip;
        renderTop7Buttons();
        renderDropdown();

        const dev = devicesData.find(d => d.ip === ip) || { ip, hostname: ip, name: ip };

        if (dev.in_proxy_hosts === false) {
            if (warningDeviceMsg) warningDeviceMsg.textContent =
                `⚠️  '${dev.name}' (${dev.ip}) is NOT in router/proxy-hosts.conf — blocking rules won't apply until it is added!`;
            if (proxyHostsWarning) proxyHostsWarning.classList.remove('hidden');
        } else {
            if (proxyHostsWarning) proxyHostsWarning.classList.add('hidden');
        }

        const pol = ensurePolicy(ip);
        syncCategoryControls(pol);
        refreshDbTabsUI();
        updateRulesPreview();

        if (saveStatusText) saveStatusText.textContent = `Editing: ${dev.name} (${dev.ip}) — click Apply to push to Squid.`;
    }

    // ─────────────────────────────────────────────────────────────
    // RENDER BLOCKLIST CHECKBOXES
    // ─────────────────────────────────────────────────────────────
    function renderAllBlocklistCheckboxes() {
        buildSectionCheckboxes(alwaysBlockCheckboxes, 'ab-', onAlwaysBlockChange);
        buildSectionCheckboxes(alwaysAllowCheckboxes, 'aa-', onAlwaysAllowChange);
        if (currentDeviceIp) renderDefaultBlockLists(ensurePolicy(currentDeviceIp));
    }

    function buildSectionCheckboxes(container, idPrefix, onChange) {
        if (!container) return;
        container.innerHTML = '';
        blocklistsData.forEach(bl => {
            const label = document.createElement('label');
            label.className = 'blocklist-chip';
            label.dataset.list = bl;
            label.innerHTML = `
                <input type="checkbox" id="${idPrefix}${bl}" value="${bl}">
                <span class="bl-name">🛡️ ${displayName(bl)}</span>
                <a href="/api/blocklists/${bl}" target="_blank" class="bl-view-btn" title="View content of ${bl}" onclick="event.stopPropagation();">↗</a>
            `;
            label.querySelector('input').addEventListener('change', (e) => onChange(bl, e.target.checked));
            container.appendChild(label);
        });
    }

    function onAlwaysBlockChange(bl, checked) {
        if (!currentDeviceIp) return;
        const pol = ensurePolicy(currentDeviceIp);
        if (checked) {
            if (!pol.always_block.includes(bl)) pol.always_block.push(bl);
            pol.always_allow = pol.always_allow.filter(x => x !== bl);
        } else {
            pol.always_block = pol.always_block.filter(x => x !== bl);
        }
        reconcileDefaultBlock(pol);
        syncCategoryControls(pol);
        refreshDbTabsUI();
        updateRulesPreview();
        scheduleAutoSave();
    }

    function onAlwaysAllowChange(bl, checked) {
        if (!currentDeviceIp) return;
        const pol = ensurePolicy(currentDeviceIp);
        if (checked) {
            if (!pol.always_allow.includes(bl)) pol.always_allow.push(bl);
            pol.always_block = pol.always_block.filter(x => x !== bl);
        } else {
            pol.always_allow = pol.always_allow.filter(x => x !== bl);
        }
        reconcileDefaultBlock(pol);
        syncCategoryControls(pol);
        refreshDbTabsUI();
        updateRulesPreview();
        scheduleAutoSave();
    }

    function syncCategoryControls(pol) {
        alwaysBlockCheckboxes && alwaysBlockCheckboxes.querySelectorAll('input[type="checkbox"]').forEach(chk => {
            chk.checked = pol.always_block.includes(chk.value);
            // Always Allow categories stay visible here because selecting them
            // promotes them to the higher-priority Always Block policy.
            chk.closest('.blocklist-chip').classList.remove('hidden');
        });
        alwaysAllowCheckboxes && alwaysAllowCheckboxes.querySelectorAll('input[type="checkbox"]').forEach(chk => {
            chk.checked = pol.always_allow.includes(chk.value);
            // Use the app's !important display utility. The blocklist chip's
            // author-level display rule can otherwise override HTML [hidden].
            chk.closest('.blocklist-chip').classList.toggle(
                'hidden', pol.always_block.includes(chk.value)
            );
        });
        renderDefaultBlockLists(pol);
    }

    function renderDefaultBlockLists(pol) {
        if (!defaultBlockLists) return;
        defaultBlockLists.innerHTML = '';
        pol.default_block.forEach(entry => {
            const bl = entry.list;
            const chip = document.createElement('div');
            chip.className = 'blocklist-chip';
            chip.dataset.list = bl;
            chip.innerHTML = `
                <span class="bl-name">🛡️ ${displayName(bl)}</span>
                <a href="/api/blocklists/${bl}" target="_blank" class="bl-view-btn" title="View content of ${bl}">↗</a>
            `;
            defaultBlockLists.appendChild(chip);
        });
    }

    // ─────────────────────────────────────────────────────────────
    // BASIC / ADVANCED SCHEDULE MODE TOGGLE
    // ─────────────────────────────────────────────────────────────
    modeBasicBtn && modeBasicBtn.addEventListener('click', () => setSchedEditMode('basic'));
    modeAdvancedBtn && modeAdvancedBtn.addEventListener('click', () => setSchedEditMode('advanced'));

    function setSchedEditMode(mode) {
        schedEditMode = mode;
        modeBasicBtn    && modeBasicBtn.classList.toggle('active', mode === 'basic');
        modeAdvancedBtn && modeAdvancedBtn.classList.toggle('active', mode === 'advanced');
        advancedMultiNote && advancedMultiNote.classList.toggle('hidden', mode === 'basic');
        refreshDbTabsUI();
    }

    // ─────────────────────────────────────────────────────────────
    // DEFAULT BLOCK TABS UI
    // ─────────────────────────────────────────────────────────────
    function refreshDbTabsUI() {
        if (!currentDeviceIp) return;
        const pol   = ensurePolicy(currentDeviceIp);
        const lists = pol.default_block.map(e => e.list);

        if (lists.length === 0) {
            dbListTabsContainer && dbListTabsContainer.classList.add('hidden');
            dbEmptyState && dbEmptyState.classList.remove('hidden');
            return;
        }

        dbEmptyState && dbEmptyState.classList.add('hidden');
        dbListTabsContainer && dbListTabsContainer.classList.remove('hidden');

        if (schedEditMode === 'basic') {
            // Basic: no tabs, no multi-select — edit all lists together
            if (dbListTabs) {
                dbListTabs.innerHTML = '<span class="basic-mode-note">All default lists share this schedule</span>';
            }
        } else {
            // Advanced: show per-list tabs, allow multi-select
            // Ensure activeListNames only contains lists that are still in default_block
            activeListNames = activeListNames.filter(n => lists.includes(n));
            // Default: select all if nothing selected
            if (activeListNames.length === 0 && lists.length > 0) {
                activeListNames = [lists[0]];
            }

            if (dbListTabs) {
                dbListTabs.innerHTML = '';
                lists.forEach(bl => {
                    const btn = document.createElement('button');
                    btn.type = 'button';
                    btn.className = `db-tab-btn ${activeListNames.includes(bl) ? 'active' : ''}`;
                    btn.innerHTML = `<span>${displayName(bl)}</span><a href="/api/blocklists/${bl}" target="_blank" class="bl-tab-view" title="View content of ${bl}" onclick="event.stopPropagation();">↗</a>`;
                    btn.title = `Click to select ${displayName(bl)} for schedule. Click ↗ to view file content.`;
                    btn.addEventListener('click', (e) => {
                        if (e.ctrlKey || e.metaKey) {
                            // Toggle this list in multi-selection
                            if (activeListNames.includes(bl)) {
                                if (activeListNames.length > 1) activeListNames = activeListNames.filter(n => n !== bl);
                            } else {
                                activeListNames.push(bl);
                            }
                        } else {
                            activeListNames = [bl];
                        }
                        refreshDbTabsUI();
                        syncMatrixToActiveEntries();
                    });
                    dbListTabs.appendChild(btn);
                });
            }
        }

        syncMatrixToActiveEntries();
    }

    // ─────────────────────────────────────────────────────────────
    // WEEKLY / TODAY MODE TOGGLE
    // ─────────────────────────────────────────────────────────────
    modeWeeklyBtn && modeWeeklyBtn.addEventListener('click', () => {
        scheduleMode = 'weekly';
        modeWeeklyBtn.classList.add('active');
        modeTodayBtn && modeTodayBtn.classList.remove('active');
        weeklyTableWrap && weeklyTableWrap.classList.remove('hidden');
        todayTableWrap && todayTableWrap.classList.add('hidden');
        todayModeHint && todayModeHint.classList.add('hidden');
        if (matrixTitle) matrixTitle.textContent = '⏰ Weekly Unblock Schedule';
        if (matrixSubtitle) matrixSubtitle.innerHTML = 'Drag to mark <strong class="allow-text">green = allowed</strong> windows. Empty = blocked by default.';
        syncMatrixToActiveEntries();
        scrollToCurrentTime();
    });

    modeTodayBtn && modeTodayBtn.addEventListener('click', () => {
        scheduleMode = 'today';
        modeTodayBtn.classList.add('active');
        modeWeeklyBtn && modeWeeklyBtn.classList.remove('active');
        weeklyTableWrap && weeklyTableWrap.classList.add('hidden');
        todayTableWrap && todayTableWrap.classList.remove('hidden');
        todayModeHint && todayModeHint.classList.remove('hidden');
        if (matrixTitle) matrixTitle.textContent = `⏰ Today-Only Override (${todayDisplayName()})`;
        if (matrixSubtitle) matrixSubtitle.innerHTML = 'Drag to allow for <strong>today only</strong>. Resets at midnight.';
        if (todayColHeader) todayColHeader.textContent = `Today (${todayDisplayName()})`;
        syncMatrixToActiveEntries();
        scrollToCurrentTime();
    });

    // ─────────────────────────────────────────────────────────────
    // BUILD GRIDS (once at startup)
    // ─────────────────────────────────────────────────────────────
    function buildWeeklyGrid() {
        if (!matrixTableBody) return;
        matrixTableBody.innerHTML = '';
        for (let s = 0; s < 48; s++) {
            const tr = document.createElement('tr');
            const tdHdr = document.createElement('td');
            tdHdr.className = 'slot-header';
            tdHdr.textContent = slotLabel(s);
            tdHdr.addEventListener('click', () => { toggleWeeklyRow(s); updateRulesPreview(); scheduleAutoSave(); });
            tr.appendChild(tdHdr);

            for (let d = 0; d < 7; d++) {
                const td = document.createElement('td');
                td.className = 'matrix-cell';
                td.dataset.day = d; td.dataset.slot = s;
                td.addEventListener('mousedown', (e) => {
                    if (e.button !== 0 || !currentDeviceIp) return;
                    e.preventDefault(); isDragging = true;
                    const lists = editingLists();
                    if (!lists.length) return;
                    const pol = ensurePolicy(currentDeviceIp);
                    const firstEntry = getOrCreateDbEntry(pol, lists[0]);
                    dragAllowValue = !(firstEntry.unblock_weekly[d] && firstEntry.unblock_weekly[d][s]);
                    applyWeeklyCell(d, s, dragAllowValue);
                    updateRulesPreview(); scheduleAutoSave();
                });
                td.addEventListener('mouseenter', () => {
                    if (isDragging && currentDeviceIp) {
                        applyWeeklyCell(d, s, dragAllowValue);
                        updateRulesPreview(); scheduleAutoSave();
                    }
                });
                tr.appendChild(td);
            }
            matrixTableBody.appendChild(tr);
        }

        matrixTableHead && matrixTableHead.querySelectorAll('th.day-col').forEach(th => {
            th.addEventListener('click', () => { toggleWeeklyColumn(parseInt(th.dataset.day, 10)); updateRulesPreview(); scheduleAutoSave(); });
        });
    }

    function buildTodayGrid() {
        if (!todayTableBody) return;
        todayTableBody.innerHTML = '';
        for (let s = 0; s < 48; s++) {
            const tr = document.createElement('tr');
            const tdHdr = document.createElement('td');
            tdHdr.className = 'slot-header';
            tdHdr.textContent = slotLabel(s);
            tdHdr.addEventListener('click', () => { toggleTodaySlot(s); updateRulesPreview(); scheduleAutoSave(); });
            tr.appendChild(tdHdr);

            const td = document.createElement('td');
            td.className = 'matrix-cell';
            td.dataset.slot = s;
            td.addEventListener('mousedown', (e) => {
                if (e.button !== 0 || !currentDeviceIp) return;
                e.preventDefault(); isDragging = true;
                const lists = editingLists();
                if (!lists.length) return;
                const pol = ensurePolicy(currentDeviceIp);
                const firstEntry = getOrCreateDbEntry(pol, lists[0]);
                dragAllowValue = !firstEntry.unblock_today[s];
                applyTodayCell(s, dragAllowValue);
                updateRulesPreview(); scheduleAutoSave();
            });
            td.addEventListener('mouseenter', () => {
                if (isDragging && currentDeviceIp) {
                    applyTodayCell(s, dragAllowValue);
                    updateRulesPreview(); scheduleAutoSave();
                }
            });
            tr.appendChild(td);
            todayTableBody.appendChild(tr);
        }
    }

    document.addEventListener('mouseup', () => { isDragging = false; });
    document.addEventListener('dragstart', (e) => { if (isDragging) e.preventDefault(); });

    // ─────────────────────────────────────────────────────────────
    // CELL APPLY — writes to ALL currently editing lists
    // ─────────────────────────────────────────────────────────────
    function applyWeeklyCell(day, slot, allowed) {
        if (!currentDeviceIp) return;
        const pol = ensurePolicy(currentDeviceIp);
        const targets = editingLists();
        targets.forEach(bl => {
            const entry = getOrCreateDbEntry(pol, bl);
            entry.unblock_weekly[day][slot] = allowed;
        });
        // Visual: show union (any list allowed → green)
        const cell = matrixTableBody && matrixTableBody.querySelector(`td[data-day="${day}"][data-slot="${slot}"]`);
        setCellVisual(cell, allowed);
    }

    function applyTodayCell(slot, allowed) {
        if (!currentDeviceIp) return;
        const pol = ensurePolicy(currentDeviceIp);
        const targets = editingLists();
        targets.forEach(bl => {
            const entry = getOrCreateDbEntry(pol, bl);
            entry.unblock_today[slot] = allowed;
        });
        const cell = todayTableBody && todayTableBody.querySelector(`td[data-slot="${slot}"]`);
        setCellVisual(cell, allowed);
    }

    function setCellVisual(cell, allowed) {
        if (!cell) return;
        if (allowed) { cell.classList.add('allowed'); cell.textContent = '✅'; }
        else         { cell.classList.remove('allowed'); cell.textContent = ''; }
    }

    /**
     * Sync the visible matrix to the UNION of all currently editing lists.
     * A slot appears green if ANY of the selected lists has it allowed.
     */
    function syncMatrixToActiveEntries() {
        if (!currentDeviceIp) return;
        const pol     = ensurePolicy(currentDeviceIp);
        const targets = editingLists();

        if (scheduleMode === 'weekly') {
            if (!matrixTableBody) return;
            for (let d = 0; d < 7; d++) {
                for (let s = 0; s < 48; s++) {
                    const allowed = targets.some(bl => {
                        const entry = pol.default_block.find(e => e.list === bl);
                        return entry && entry.unblock_weekly[d] && entry.unblock_weekly[d][s];
                    });
                    const cell = matrixTableBody.querySelector(`td[data-day="${d}"][data-slot="${s}"]`);
                    setCellVisual(cell, allowed);
                }
            }
        } else {
            if (!todayTableBody) return;
            for (let s = 0; s < 48; s++) {
                const allowed = targets.some(bl => {
                    const entry = pol.default_block.find(e => e.list === bl);
                    return entry && entry.unblock_today && entry.unblock_today[s];
                });
                const cell = todayTableBody.querySelector(`td[data-slot="${s}"]`);
                setCellVisual(cell, allowed);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────
    // ROW / COLUMN TOGGLES
    // ─────────────────────────────────────────────────────────────
    function toggleWeeklyRow(slot) {
        const targets = editingLists();
        if (!targets.length || !currentDeviceIp) return;
        const pol = ensurePolicy(currentDeviceIp);
        // Toggle off if ALL selected lists AND all days are allowed, else turn on all
        const allOn = targets.every(bl => {
            const entry = pol.default_block.find(e => e.list === bl);
            return entry && Array.from({length:7}, (_,d) => entry.unblock_weekly[d][slot]).every(Boolean);
        });
        for (let d = 0; d < 7; d++) applyWeeklyCell(d, slot, !allOn);
    }

    function toggleWeeklyColumn(day) {
        const targets = editingLists();
        if (!targets.length || !currentDeviceIp) return;
        const pol = ensurePolicy(currentDeviceIp);
        const allOn = targets.every(bl => {
            const entry = pol.default_block.find(e => e.list === bl);
            return entry && entry.unblock_weekly[day].every(Boolean);
        });
        for (let s = 0; s < 48; s++) applyWeeklyCell(day, s, !allOn);
    }

    function toggleTodaySlot(slot) {
        const targets = editingLists();
        if (!targets.length || !currentDeviceIp) return;
        const pol = ensurePolicy(currentDeviceIp);
        const allOn = targets.every(bl => {
            const entry = pol.default_block.find(e => e.list === bl);
            return entry && entry.unblock_today[slot];
        });
        applyTodayCell(slot, !allOn);
    }

    // ─────────────────────────────────────────────────────────────
    // AUTO-SCROLL
    // ─────────────────────────────────────────────────────────────
    function scrollToCurrentTime() {
        const now = new Date();
        const startSlot = Math.floor((now.getHours() * 60 + now.getMinutes()) / 30);
        const containerId = scheduleMode === 'weekly' ? 'weekly-table-wrap' : 'today-table-wrap';
        const container = document.getElementById(containerId);
        if (!container) return;
        
        const firstCell = container.querySelector(`td[data-slot="${startSlot}"]`);
        if (firstCell) {
            const tr = firstCell.parentElement;
            container.scrollTo({
                top: tr.offsetTop - 40,
                behavior: 'smooth'
            });
        }
    }

    // ─────────────────────────────────────────────────────────────
    // PRESETS
    // ─────────────────────────────────────────────────────────────
    presetAllowAll && presetAllowAll.addEventListener('click', () => {
        if (!currentDeviceIp || !editingLists().length) return;
        if (scheduleMode === 'weekly') { for (let d=0;d<7;d++) for (let s=0;s<48;s++) applyWeeklyCell(d,s,true); }
        else { for (let s=0;s<48;s++) applyTodayCell(s,true); }
        updateRulesPreview(); scheduleAutoSave();
    });
    presetBlockAll && presetBlockAll.addEventListener('click', () => {
        if (!currentDeviceIp || !editingLists().length) return;
        if (scheduleMode === 'weekly') { for (let d=0;d<7;d++) for (let s=0;s<48;s++) applyWeeklyCell(d,s,false); }
        else { for (let s=0;s<48;s++) applyTodayCell(s,false); }
        updateRulesPreview(); scheduleAutoSave();
    });
    
    function applyNextDuration(durationMins) {
        if (!currentDeviceIp || !editingLists().length) return;
        const now = new Date();
        const currentMins = now.getHours() * 60 + now.getMinutes();
        const startSlot = Math.floor(currentMins / 30);
        const endSlot = Math.ceil((currentMins + durationMins) / 30) - 1;
        
        // Ensure bounds
        const sStart = Math.max(0, Math.min(47, startSlot));
        const sEnd = Math.max(0, Math.min(47, endSlot));
        
        if (scheduleMode === 'weekly') {
            const todayDay = now.getDay();
            for (let s = sStart; s <= sEnd; s++) applyWeeklyCell(todayDay, s, true);
        } else {
            for (let s = sStart; s <= sEnd; s++) applyTodayCell(s, true);
        }
        updateRulesPreview(); scheduleAutoSave();
    }

    presetNext30m && presetNext30m.addEventListener('click', () => applyNextDuration(30));
    presetNext1h && presetNext1h.addEventListener('click', () => applyNextDuration(60));
    presetNext2h && presetNext2h.addEventListener('click', () => applyNextDuration(120));

    // ─────────────────────────────────────────────────────────────
    // AUTO-SAVE
    // ─────────────────────────────────────────────────────────────
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
            } catch (_) {}
        }, 800);
    }

    // ─────────────────────────────────────────────────────────────
    // REAL-TIME RULES PREVIEW
    // ─────────────────────────────────────────────────────────────
    function updateRulesPreview() {
        if (!rulesPreviewTextbox) return;
        const pol = currentDeviceIp ? ensurePolicy(currentDeviceIp) : null;
        const dev = devicesData.find(d => d.ip === currentDeviceIp);
        if (!pol || !dev) { rulesPreviewTextbox.value = '# Select a device to see generated rules.'; return; }

        const srcAcl = `src_dev_${dev.ip.replace(/\./g,'_')}`;
        const lines = [
            `# ${'='.repeat(60)}`,
            `# SQUID ACL — ${dev.name} (${dev.ip})`,
            `# Generated: ${new Date().toLocaleString()}`,
            `# ${'='.repeat(60)}`, '',
            `acl ${srcAcl} src ${dev.ip}`, ''
        ];

        const allLists = [...new Set([
            ...(pol.always_block || []),
            ...(pol.always_allow || []),
            ...(pol.default_block || []).map(e => e.list)
        ])];
        allLists.forEach(bl => {
            lines.push(`acl list_${bl.replace(/[.\-]/g,'_')} dstdomain "/etc/squid/block-lists/${bl}"`);
        });
        lines.push('');

        if (pol.always_block && pol.always_block.length) {
            lines.push('# ── Always Block (unconditional) ──');
            pol.always_block.forEach(bl => lines.push(`http_access deny ${srcAcl} list_${bl.replace(/[.\-]/g,'_')}`));
            lines.push('');
        }

        if (pol.always_allow && pol.always_allow.length) {
            lines.push('# ── Always Allow (unconditional) ──');
            pol.always_allow.forEach(bl => lines.push(`http_access allow ${srcAcl} list_${bl.replace(/[.\-]/g,'_')}`));
            lines.push('');
        }

        let idx = 0;
        (pol.default_block || []).forEach(entry => {
            const bl = entry.list; if (!bl) return;
            const blAcl = `list_${bl.replace(/[.\-]/g,'_')}`;
            lines.push(`# ── Default Block: ${displayName(bl)} ──`);
            const weekly  = entry.unblock_weekly || makeEmptyWeekly();
            const today   = entry.unblock_today  || makeEmptyToday();
            const todayDay = new Date().getDay();
            const merged  = weekly.map((row, d) => d !== todayDay ? row : row.map((v,s) => v || today[s]));
            const rangeToDays = {};
            for (let d=0;d<7;d++) {
                const daySlots = merged[d] || [];
                let inRange=false, startSlot=0;
                for (let s=0;s<48;s++) {
                    if (daySlots[s] && !inRange) { inRange=true; startSlot=s; }
                    else if (!daySlots[s] && inRange) {
                        inRange=false;
                        const k=`${slotStart(startSlot)}-${slotEnd(s-1)}`;
                        (rangeToDays[k]=rangeToDays[k]||[]).push(DAY_LETTERS[d]);
                    }
                }
                if (inRange) { const k=`${slotStart(startSlot)}-${slotEnd(47)}`; (rangeToDays[k]=rangeToDays[k]||[]).push(DAY_LETTERS[d]); }
            }
            Object.entries(rangeToDays).forEach(([tr,days])=>{
                const ta=`time_allow_${dev.ip.replace(/\./g,'_')}_${idx++}`;
                lines.push(`acl ${ta} time ${days.join('')} ${tr}`);
                lines.push(`http_access allow ${srcAcl} ${blAcl} ${ta}`);
            });
            lines.push(`http_access deny ${srcAcl} ${blAcl}`, '');
        });

        const bumpedLists = [
            ...(pol.always_block || []),
            ...(pol.default_block || []).map(e => e.list)
        ];
        if (bumpedLists.length) {
            lines.push('# ── Dynamic SSL Bump (Intercept blocked sites for HTML block page) ──');
            bumpedLists.forEach(bl => {
                lines.push(`ssl_bump bump ${srcAcl} list_${bl.replace(/[.\-]/g,'_')}`);
            });
            lines.push('');
        }

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

    // ─────────────────────────────────────────────────────────────
    // APPLY
    // ─────────────────────────────────────────────────────────────
    applyPolicyBtn && applyPolicyBtn.addEventListener('click', async () => {
        if (!isAuthenticated) { authModal.classList.remove('hidden'); return; }
        applyPolicyBtn.disabled = true;
        saveStatusText.textContent = '⏳ Saving & compiling Squid ACLs…';
        try {
            const saveRes = await fetch('/api/policies', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ policies: devicePolicies })
            });
            const saveData = await saveRes.json().catch(() => ({}));
            if (!saveRes.ok || saveData.success === false) {
                throw new Error(saveData.error || saveData.message || `Save failed (HTTP ${saveRes.status})`);
            }
            const applyRes  = await fetch('/api/apply', { method: 'POST' });
            const applyData = await applyRes.json().catch(() => ({}));
            saveStatusText.textContent = applyRes.ok && applyData.success !== false
                ? '✅ Policies applied — Squid reloaded successfully!'
                : `❌ Apply failed: ${applyData.message || applyData.error || 'Unknown error'}`;
        } catch (err) {
            saveStatusText.textContent = `❌ Error: ${err.message}`;
        } finally {
            applyPolicyBtn.disabled = false;
        }
    });

    // Initialize visual state based on default scheduleMode
    if (scheduleMode === 'today') {
        modeTodayBtn && modeTodayBtn.click();
    } else {
        modeWeeklyBtn && modeWeeklyBtn.click();
    }
});
