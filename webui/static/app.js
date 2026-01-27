document.addEventListener('DOMContentLoaded', () => {
    // Nav Elements
    const navTabOnboarding = document.getElementById('nav-tab-onboarding');
    const navTabAdmin = document.getElementById('nav-tab-admin');
    const onboardingScreen = document.getElementById('onboarding-screen');
    const adminScreen = document.getElementById('admin-screen');
    
    const userBadge = document.getElementById('user-badge');
    const currentUserSpan = document.getElementById('current-user');
    const authActionBtn = document.getElementById('auth-action-btn');

    // Guide Platform Tab Elements
    const guideTabWindows = document.getElementById('guide-tab-windows');
    const guideTabUbuntu = document.getElementById('guide-tab-ubuntu');
    const guideContentWindows = document.getElementById('guide-content-windows');
    const guideContentUbuntu = document.getElementById('guide-content-ubuntu');

    // Auth Modal Elements
    const authModal = document.getElementById('auth-modal');
    const authModalClose = document.getElementById('auth-modal-close');
    const loginForm = document.getElementById('login-form');
    const loginError = document.getElementById('login-error');

    // Admin Dashboard Elements
    const addRuleBtn = document.getElementById('add-rule-btn');
    const rulesList = document.getElementById('rules-list');
    const emptyState = document.getElementById('empty-state');
    
    // Rule Modal Elements
    const ruleModal = document.getElementById('rule-modal');
    const ruleForm = document.getElementById('rule-form');
    const modalTitle = document.getElementById('modal-title');
    const modalClose = document.getElementById('modal-close');
    const cancelRuleBtn = document.getElementById('cancel-rule-btn');
    
    const deviceSelect = document.getElementById('device-select');
    const customIp = document.getElementById('custom-ip');
    const blocklistSelect = document.getElementById('blocklist-select');

    // State
    let isAuthenticated = false;
    let currentUser = '';
    let hostsData = [];
    let blocklistsData = [];
    let rulesData = [];

    // Check Auth Status on Load
    checkAuthStatus();

    async function checkAuthStatus() {
        try {
            const res = await fetch('/api/auth/status');
            const data = await res.json();
            isAuthenticated = data.authenticated;
            currentUser = data.user || '';
            updateAuthUI();
        } catch (e) {
            console.error('Auth check error:', e);
            isAuthenticated = false;
            updateAuthUI();
        }
    }

    function updateAuthUI() {
        if (isAuthenticated) {
            userBadge.classList.remove('hidden');
            currentUserSpan.textContent = currentUser;
            authActionBtn.textContent = 'Logout';
        } else {
            userBadge.classList.add('hidden');
            authActionBtn.textContent = 'Admin Login';
        }
    }

    // Top Nav Tabs
    navTabOnboarding.addEventListener('click', () => {
        navTabOnboarding.classList.add('active');
        navTabAdmin.classList.remove('active');
        onboardingScreen.classList.remove('hidden');
        adminScreen.classList.add('hidden');
    });

    navTabAdmin.addEventListener('click', () => {
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
        loadAdminData();
    }

    // Guide Platform Tabs
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

    // Auth Action Button (Login / Logout)
    authActionBtn.addEventListener('click', async () => {
        if (isAuthenticated) {
            await fetch('/api/logout', { method: 'POST' });
            isAuthenticated = false;
            currentUser = '';
            updateAuthUI();
            navTabOnboarding.click();
        } else {
            authModal.classList.remove('hidden');
        }
    });

    authModalClose.addEventListener('click', () => authModal.classList.add('hidden'));

    // Login Form Submit
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        loginError.classList.add('hidden');

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();
        const submitBtn = document.getElementById('login-btn');

        submitBtn.disabled = true;
        submitBtn.textContent = 'Authenticating...';

        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const data = await res.json();

            if (res.ok && data.success) {
                isAuthenticated = true;
                currentUser = username;
                updateAuthUI();
                authModal.classList.add('hidden');
                switchToAdmin();
            } else {
                loginError.textContent = data.error || 'Authentication failed.';
                loginError.classList.remove('hidden');
            }
        } catch (e) {
            loginError.textContent = 'Server connection error. Please try again.';
            loginError.classList.remove('hidden');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Authenticate';
        }
    });

    // Admin Dashboard Data
    async function loadAdminData() {
        await Promise.all([fetchHosts(), fetchBlocklists(), fetchRules()]);
    }

    async function fetchHosts() {
        try {
            const res = await fetch('/api/hosts');
            const data = await res.json();
            hostsData = data.hosts || [];
            populateDeviceSelect();
        } catch (e) {
            console.error('Error loading hosts:', e);
        }
    }

    async function fetchBlocklists() {
        try {
            const res = await fetch('/api/blocklists');
            const data = await res.json();
            blocklistsData = data.blocklists || [];
            populateBlocklistSelect();
        } catch (e) {
            console.error('Error loading blocklists:', e);
        }
    }

    async function fetchRules() {
        try {
            const res = await fetch('/api/rules');
            const data = await res.json();
            rulesData = data.rules || [];
            renderRules();
        } catch (e) {
            console.error('Error loading rules:', e);
        }
    }

    function populateDeviceSelect() {
        deviceSelect.innerHTML = '<option value="">-- Select from Known Devices --</option>';
        hostsData.forEach(h => {
            const opt = document.createElement('option');
            opt.value = h.ip;
            opt.textContent = `${h.hostname} (${h.ip})`;
            deviceSelect.appendChild(opt);
        });
    }

    function populateBlocklistSelect() {
        blocklistSelect.innerHTML = '';
        blocklistsData.forEach(b => {
            const opt = document.createElement('option');
            opt.value = b;
            opt.textContent = b;
            blocklistSelect.appendChild(opt);
        });
    }

    function renderRules() {
        rulesList.innerHTML = '';
        if (rulesData.length === 0) {
            emptyState.classList.remove('hidden');
            return;
        }
        emptyState.classList.add('hidden');

        rulesData.forEach(r => {
            const tr = document.createElement('tr');
            
            const daysText = r.days && r.days.length > 0 ? r.days.map(d => d.slice(0, 3)).join(', ') : 'Everyday';
            const timeText = `${r.time_start} - ${r.time_end}`;
            const targetDevice = r.source_name ? `${r.source_name} (${r.source_ip})` : r.source_ip;
            const policyBadge = r.policy === 'allow_during_slot' 
                ? '<span style="color: #6ee7b7;">Allow in window</span>' 
                : '<span style="color: #fca5a5;">Block in window</span>';

            tr.innerHTML = `
                <td>
                    <span class="status-pill ${r.enabled ? 'active' : 'inactive'}">
                        ${r.enabled ? '● Active' : '○ Disabled'}
                    </span>
                </td>
                <td><strong>${escapeHtml(r.name)}</strong></td>
                <td>${escapeHtml(targetDevice)}</td>
                <td><code>${escapeHtml(r.blocklist)}</code></td>
                <td>${daysText} (${timeText})</td>
                <td>${policyBadge}</td>
                <td class="text-right">
                    <button class="btn btn-secondary btn-sm toggle-btn" data-id="${r.id}">
                        ${r.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button class="btn btn-secondary btn-sm edit-btn" data-id="${r.id}">Edit</button>
                    <button class="btn btn-secondary btn-sm delete-btn" data-id="${r.id}" style="color:#ef4444;">Delete</button>
                </td>
            `;

            rulesList.appendChild(tr);
        });

        document.querySelectorAll('.toggle-btn').forEach(btn => {
            btn.addEventListener('click', () => toggleRule(btn.dataset.id));
        });
        document.querySelectorAll('.edit-btn').forEach(btn => {
            btn.addEventListener('click', () => editRule(btn.dataset.id));
        });
        document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', () => deleteRule(btn.dataset.id));
        });
    }

    // Modal Controls
    addRuleBtn.addEventListener('click', () => {
        resetForm();
        modalTitle.textContent = 'Add Access Rule';
        ruleModal.classList.remove('hidden');
    });

    modalClose.addEventListener('click', () => ruleModal.classList.add('hidden'));
    cancelRuleBtn.addEventListener('click', () => ruleModal.classList.add('hidden'));

    deviceSelect.addEventListener('change', () => {
        if (deviceSelect.value) customIp.value = '';
    });
    customIp.addEventListener('input', () => {
        if (customIp.value) deviceSelect.value = '';
    });

    // Save Rule
    ruleForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const ruleId = document.getElementById('rule-id').value;
        const name = document.getElementById('rule-name').value.trim();
        const selectedIp = customIp.value.trim() || deviceSelect.value;
        
        let selectedHostName = '';
        if (deviceSelect.value) {
            const hostObj = hostsData.find(h => h.ip === deviceSelect.value);
            if (hostObj) selectedHostName = hostObj.hostname;
        }

        if (!selectedIp) {
            alert('Please select a device or enter a custom IP address.');
            return;
        }

        const blocklist = blocklistSelect.value;
        const days = Array.from(document.querySelectorAll('input[name="days"]:checked')).map(cb => cb.value);
        const timeStart = document.getElementById('time-start').value;
        const timeEnd = document.getElementById('time-end').value;
        const policy = document.getElementById('rule-policy').value;

        const payload = {
            id: ruleId || undefined,
            name,
            source_ip: selectedIp,
            source_name: selectedHostName,
            blocklist,
            days,
            time_start: timeStart,
            time_end: timeEnd,
            policy,
            enabled: true
        };

        try {
            const res = await fetch('/api/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (res.ok) {
                ruleModal.classList.add('hidden');
                fetchRules();
            } else {
                alert('Failed to save rule.');
            }
        } catch (e) {
            console.error('Error saving rule:', e);
        }
    });

    async function toggleRule(ruleId) {
        try {
            await fetch(`/api/rules/${ruleId}/toggle`, { method: 'POST' });
            fetchRules();
        } catch (e) {
            console.error('Error toggling rule:', e);
        }
    }

    async function deleteRule(ruleId) {
        if (!confirm('Are you sure you want to delete this rule?')) return;
        try {
            await fetch(`/api/rules/${ruleId}`, { method: 'DELETE' });
            fetchRules();
        } catch (e) {
            console.error('Error deleting rule:', e);
        }
    }

    function editRule(ruleId) {
        const rule = rulesData.find(r => r.id === ruleId);
        if (!rule) return;

        document.getElementById('rule-id').value = rule.id;
        document.getElementById('rule-name').value = rule.name;

        if (hostsData.some(h => h.ip === rule.source_ip)) {
            deviceSelect.value = rule.source_ip;
            customIp.value = '';
        } else {
            deviceSelect.value = '';
            customIp.value = rule.source_ip;
        }

        blocklistSelect.value = rule.blocklist;
        document.getElementById('time-start').value = rule.time_start;
        document.getElementById('time-end').value = rule.time_end;
        document.getElementById('rule-policy').value = rule.policy;

        document.querySelectorAll('input[name="days"]').forEach(cb => {
            cb.checked = rule.days ? rule.days.includes(cb.value) : true;
        });

        modalTitle.textContent = 'Edit Access Rule';
        ruleModal.classList.remove('hidden');
    }

    function resetForm() {
        document.getElementById('rule-id').value = '';
        document.getElementById('rule-form').reset();
        document.querySelectorAll('input[name="days"]').forEach(cb => cb.checked = true);
    }

    function escapeHtml(str) {
        return (str || '').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }
});
