(() => {
    let screen = null;
    let quickButtons = [];
    let prevDayBtn = null;
    let todayBtn = null;
    let nextDayBtn = null;
    let datePicker = null;
    let clientFilter = null;
    let quickDevicesContainer = null;
    let domainFilter = null;
    let refreshBtn = null;
    let cacheBadge = null;

    let kpiTotal = null;
    let kpiDomains = null;
    let kpiClients = null;
    let kpiCategory = null;
    let categoryPills = null;

    let loadingIndicator = null;
    let emptyState = null;
    let failuresList = null;
    let initialized = false;

    let currentMode = "date"; // "date" (Day) or "window" (sub-day: 5m..5h)
    let currentWindow = "day";
    let currentDate = localToday();
    let currentClientIp = "";
    let loadedEvents = [];
    let clientsLoaded = false;
    let currentFetchController = null;

    function localToday() {
        const d = new Date();
        const year = d.getFullYear();
        const month = String(d.getMonth() + 1).padStart(2, "0");
        const day = String(d.getDate()).padStart(2, "0");
        return `${year}-${month}-${day}`;
    }

    function addDays(isoDate, days) {
        if (!isoDate || typeof isoDate !== "string" || !isoDate.includes("-")) {
            isoDate = localToday();
        }
        const parts = isoDate.split("-").map(Number);
        const d = new Date(parts[0], parts[1] - 1, parts[2]);
        d.setDate(d.getDate() + days);
        const year = d.getFullYear();
        const month = String(d.getMonth() + 1).padStart(2, "0");
        const day = String(d.getDate()).padStart(2, "0");
        return `${year}-${month}-${day}`;
    }

    function initDateConstraints() {
        if (!datePicker) return;
        const retentionDays = (window.WEBUI_CONTEXT && window.WEBUI_CONTEXT.failureRetentionDays) || 30;
        const today = localToday();
        datePicker.max = today;
        datePicker.min = addDays(today, -(retentionDays - 1));
        if (!datePicker.value) {
            datePicker.value = today;
        }
        currentDate = datePicker.value;
    }

    function getDeviceIcon(name) {
        const n = (name || "").toLowerCase();
        if (n.startsWith("phone"))  return "📱";
        if (n.startsWith("laptop")) return "💻";
        if (n.startsWith("pc"))     return "🖥️";
        if (n.startsWith("tablet") || n.startsWith("ipad")) return "📱";
        if (n.startsWith("tv") || n.startsWith("apple-tv")) return "📺";
        return "📟";
    }

    function selectClient(ip) {
        currentClientIp = ip || "";
        if (clientFilter) {
            clientFilter.value = currentClientIp;
        }
        syncQuickDeviceButtons();
        loadData();
    }

    function syncQuickDeviceButtons() {
        if (!quickDevicesContainer) return;
        const buttons = quickDevicesContainer.querySelectorAll(".top8-btn");
        buttons.forEach(btn => {
            btn.classList.toggle("active", (btn.dataset.ip || "") === currentClientIp);
        });
    }

    function renderQuickDeviceButtons(devices) {
        if (!quickDevicesContainer) return;
        quickDevicesContainer.replaceChildren();

        const allBtn = document.createElement("button");
        allBtn.type = "button";
        allBtn.className = `top8-btn ${currentClientIp === "" ? "active" : ""}`;
        allBtn.dataset.ip = "";
        allBtn.textContent = "🌐 All Clients";
        allBtn.addEventListener("click", () => {
            selectClient("");
        });
        quickDevicesContainer.appendChild(allBtn);

        (devices || []).forEach(dev => {
            const btn = document.createElement("button");
            btn.type = "button";
            btn.className = `top8-btn ${dev.ip === currentClientIp ? "active" : ""}`;
            btn.dataset.ip = dev.ip;
            btn.textContent = `${getDeviceIcon(dev.name)} ${dev.name || dev.hostname}`;
            btn.title = `${dev.ip} — ${dev.hostname}`;
            btn.addEventListener("click", () => {
                selectClient(dev.ip);
            });
            quickDevicesContainer.appendChild(btn);
        });
    }

    async function loadClients() {
        if (clientsLoaded) return;
        try {
            const res = await fetch("/api/devices");
            if (!res.ok) return;
            const data = await res.json();
            const devices = data.devices || [];
            if (clientFilter) {
                clientFilter.replaceChildren();

                const defaultOpt = document.createElement("option");
                defaultOpt.value = "";
                defaultOpt.textContent = "All Clients";
                clientFilter.appendChild(defaultOpt);

                devices.forEach(dev => {
                    const opt = document.createElement("option");
                    opt.value = dev.ip;
                    opt.textContent = `${dev.name || dev.hostname} (${dev.ip})`;
                    clientFilter.appendChild(opt);
                });
            }

            renderQuickDeviceButtons(devices);
            clientsLoaded = true;
        } catch (_) {}
    }

    function getStatusClass(status) {
        if (!status) return "badge-status-other";
        const s = String(status);
        if (s.startsWith("5")) return "badge-status-5xx";
        if (s === "409") return "badge-status-409";
        if (s.startsWith("4")) return "badge-status-4xx";
        if (s === "000" || s === "0") return "badge-status-000";
        return "badge-status-other";
    }

    function renderCategoryPills(categories) {
        if (!categoryPills) return;
        categoryPills.replaceChildren();
        if (!categories || Object.keys(categories).length === 0) return;

        Object.entries(categories).forEach(([cat, count]) => {
            const pill = document.createElement("span");
            pill.className = "category-pill";
            pill.textContent = `${cat}: ${count}`;
            categoryPills.appendChild(pill);
        });
    }

    function renderEventCard(event) {
        const card = document.createElement("div");
        card.className = "failure-card glass-panel";
        card.dataset.domain = (event.domain || "").toLowerCase();
        card.dataset.client = (event.client_name || event.client_ip || "").toLowerCase();
        card.dataset.explanation = (event.explanation || "").toLowerCase();

        const statusClass = getStatusClass(event.status);

        card.innerHTML = `
            <div class="failure-card-header">
                <div class="failure-title-group">
                    <span class="failure-domain">${escapeHtml(event.domain)}</span>
                    <span class="failure-status-badge ${statusClass}">${escapeHtml(event.result || event.status)}</span>
                </div>
                <div class="failure-meta">
                    <span class="failure-time">🕒 ${escapeHtml(event.datetime_local)}</span>
                    <span class="failure-device-badge clickable-filter" title="Filter by ${escapeHtml(event.client_name || event.client_ip)}">${getDeviceIcon(event.client_name)} ${escapeHtml(event.client_name)} (${escapeHtml(event.client_ip)})</span>
                </div>
            </div>
            <div class="failure-destination">
                <code>${escapeHtml(event.method)} ${escapeHtml(event.url)}</code>
            </div>
            <div class="failure-explanation-box">
                <div class="explanation-title">🔍 ${escapeHtml(event.category)}</div>
                <div class="explanation-body">${escapeHtml(event.explanation)}</div>
            </div>
            <div class="failure-actions">
                <button type="button" class="btn btn-sm btn-secondary btn-copy-ai">📋 Copy for AI (Gemini/ChatGPT)</button>
                <button type="button" class="btn btn-sm btn-text btn-toggle-raw">📄 View Raw Log</button>
            </div>
            <pre class="raw-log-container hidden"><code>${escapeHtml(event.raw_log)}</code></pre>
        `;

        const deviceBadge = card.querySelector(".failure-device-badge");
        if (deviceBadge && event.client_ip) {
            deviceBadge.addEventListener("click", () => {
                selectClient(event.client_ip);
            });
        }

        const copyBtn = card.querySelector(".btn-copy-ai");
        if (copyBtn) {
            copyBtn.addEventListener("click", async () => {
                try {
                    await navigator.clipboard.writeText(event.copyable_prompt);
                    const originalText = copyBtn.textContent;
                    copyBtn.textContent = "✅ Copied to clipboard!";
                    copyBtn.classList.add("btn-success");
                    setTimeout(() => {
                        copyBtn.textContent = originalText;
                        copyBtn.classList.remove("btn-success");
                    }, 2000);
                } catch (_) {
                    alert("Failed to copy to clipboard. Please copy manually from the raw log.");
                }
            });
        }

        const toggleRawBtn = card.querySelector(".btn-toggle-raw");
        const rawContainer = card.querySelector(".raw-log-container");
        if (toggleRawBtn && rawContainer) {
            toggleRawBtn.addEventListener("click", () => {
                const isHidden = rawContainer.classList.toggle("hidden");
                toggleRawBtn.textContent = isHidden ? "📄 View Raw Log" : "📄 Hide Raw Log";
            });
        }

        return card;
    }

    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function applyClientSearch() {
        if (!domainFilter || !failuresList) return;
        const query = domainFilter.value.trim().toLowerCase();
        let visibleCount = 0;
        const cards = failuresList.querySelectorAll(".failure-card");

        cards.forEach(card => {
            const domain = card.dataset.domain;
            const client = card.dataset.client;
            const explanation = card.dataset.explanation;
            const matches = !query || domain.includes(query) || client.includes(query) || explanation.includes(query);
            card.classList.toggle("hidden", !matches);
            if (matches) visibleCount++;
        });

        if (emptyState) {
            if (cards.length > 0 && visibleCount === 0) {
                emptyState.classList.remove("hidden");
                const p = emptyState.querySelector("p");
                if (p) p.innerHTML = `🔍 No failures matching <strong>${escapeHtml(query)}</strong>.`;
            } else if (cards.length > 0) {
                emptyState.classList.add("hidden");
            }
        }
    }

    function clearCurrentStatsAndList() {
        loadedEvents = [];
        if (failuresList) failuresList.replaceChildren();
        if (emptyState) emptyState.classList.add("hidden");
        if (categoryPills) categoryPills.replaceChildren();
        if (cacheBadge) cacheBadge.classList.add("hidden");

        // Clear KPI stats immediately so previous day data is never displayed while loading
        if (kpiTotal) kpiTotal.textContent = "—";
        if (kpiDomains) kpiDomains.textContent = "—";
        if (kpiClients) kpiClients.textContent = "—";
        if (kpiCategory) kpiCategory.textContent = "—";
    }

    async function loadData() {
        if (currentFetchController) {
            currentFetchController.abort();
        }
        currentFetchController = new AbortController();

        clearCurrentStatsAndList();

        const today = localToday();
        const targetLabel = (currentMode === "date")
            ? (currentDate === today ? "today" : currentDate)
            : `last ${currentWindow}`;

        if (loadingIndicator) {
            const loadingMsg = loadingIndicator.querySelector("p");
            if (loadingMsg) {
                loadingMsg.textContent = `Analyzing Squid logs for ${targetLabel}...`;
            }
            loadingIndicator.classList.remove("hidden");
        }

        let url = "/api/failure-analytics?";
        if (currentMode === "window") {
            url += `window=${encodeURIComponent(currentWindow)}`;
        } else {
            url += `date=${encodeURIComponent(currentDate || today)}`;
        }
        if (currentClientIp) {
            url += `&client_ip=${encodeURIComponent(currentClientIp)}`;
        }

        try {
            const res = await fetch(url, { signal: currentFetchController.signal });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.error || "Failed to load failure data");
            }
            const data = await res.json();
            const summary = data.summary || {};
            loadedEvents = data.events || [];

            // Update KPI cards
            if (kpiTotal) kpiTotal.textContent = summary.total_failures || 0;
            if (kpiDomains) kpiDomains.textContent = summary.unique_domains || 0;
            if (kpiClients) kpiClients.textContent = summary.unique_clients || 0;

            const topDomain = summary.top_domains && summary.top_domains[0];
            const topCategory = topDomain ? topDomain.primary_category : (summary.category_counts && Object.keys(summary.category_counts)[0]) || "-";
            if (kpiCategory) kpiCategory.textContent = topCategory;

            // Cache badge
            if (cacheBadge) cacheBadge.classList.toggle("hidden", !data.cached);

            // Category breakdown
            renderCategoryPills(summary.category_counts);

            if (loadedEvents.length === 0) {
                if (emptyState) {
                    emptyState.classList.remove("hidden");
                    const p = emptyState.querySelector("p");
                    if (p) p.innerHTML = "🎉 <strong>No non-policy connection failures detected</strong> in this time period.";
                }
            } else {
                if (emptyState) emptyState.classList.add("hidden");
                if (failuresList) {
                    const fragment = document.createDocumentFragment();
                    loadedEvents.forEach(evt => {
                        fragment.appendChild(renderEventCard(evt));
                    });
                    failuresList.appendChild(fragment);
                }
                applyClientSearch();
            }
        } catch (err) {
            if (err.name === "AbortError") return;
            if (emptyState) {
                emptyState.classList.remove("hidden");
                const p = emptyState.querySelector("p");
                if (p) p.innerHTML = `⚠️ <strong>Error:</strong> ${escapeHtml(err.message)}`;
            }
            if (kpiTotal) kpiTotal.textContent = "0";
            if (kpiDomains) kpiDomains.textContent = "0";
            if (kpiClients) kpiClients.textContent = "0";
            if (kpiCategory) kpiCategory.textContent = "-";
        } finally {
            if (currentFetchController && !currentFetchController.signal.aborted) {
                if (loadingIndicator) loadingIndicator.classList.add("hidden");
            }
        }
    }

    function updateQuickButtonStates() {
        const today = localToday();
        const isToday = (currentDate === today);
        quickButtons.forEach(btn => {
            const win = btn.dataset.window;
            if (win === "day") {
                btn.disabled = false;
                btn.classList.remove("disabled");
                btn.classList.toggle("active", currentMode === "date" || currentWindow === "day");
                btn.title = isToday ? "View today's full day failures (default)" : `View full day failures for ${currentDate}`;
            } else {
                // Sub-day quick windows (5m - 5h) are only available for Today
                btn.disabled = !isToday;
                btn.classList.toggle("disabled", !isToday);
                if (!isToday) {
                    btn.classList.remove("active");
                    btn.title = "Sub-day quick views (5m - 5h) are only available for Today";
                } else {
                    btn.title = `View failures in last ${win}`;
                    btn.classList.toggle("active", currentMode === "window" && currentWindow === win);
                }
            }
        });

        if (nextDayBtn) {
            const atOrBeyondToday = (currentDate >= today);
            nextDayBtn.disabled = atOrBeyondToday;
            nextDayBtn.classList.toggle("disabled", atOrBeyondToday);
        }

        if (prevDayBtn && datePicker && datePicker.min) {
            const atOrPastMin = (currentDate <= datePicker.min);
            prevDayBtn.disabled = atOrPastMin;
            prevDayBtn.classList.toggle("disabled", atOrPastMin);
        }
    }

    function setupElements() {
        screen = document.getElementById("failures-screen");
        quickButtons = Array.from(document.querySelectorAll("#failures-quick-windows [data-window]"));
        prevDayBtn = document.getElementById("failures-prev-day");
        todayBtn = document.getElementById("failures-today");
        nextDayBtn = document.getElementById("failures-next-day");
        datePicker = document.getElementById("failures-date-picker");
        clientFilter = document.getElementById("failures-client-filter");
        quickDevicesContainer = document.getElementById("failures-quick-devices-buttons");
        domainFilter = document.getElementById("failures-domain-filter");
        refreshBtn = document.getElementById("failures-refresh-btn");
        cacheBadge = document.getElementById("failures-cache-badge");

        kpiTotal = document.getElementById("kpi-total-failures");
        kpiDomains = document.getElementById("kpi-failing-domains");
        kpiClients = document.getElementById("kpi-affected-devices");
        kpiCategory = document.getElementById("kpi-primary-category");
        categoryPills = document.getElementById("failures-category-pills");

        loadingIndicator = document.getElementById("failures-loading");
        emptyState = document.getElementById("failures-empty");
        failuresList = document.getElementById("failures-list");
    }

    let listenersBound = false;

    function bindEventListeners() {
        // Quick window button listeners
        quickButtons.forEach(btn => {
            btn.addEventListener("click", () => {
                const win = btn.dataset.window;
                if (win === "day") {
                    currentMode = "date";
                    currentWindow = "day";
                    updateQuickButtonStates();
                    loadData();
                } else {
                    // Clicking a sub-day window automatically scopes to today
                    currentDate = localToday();
                    if (datePicker) datePicker.value = currentDate;
                    currentMode = "window";
                    currentWindow = win;
                    updateQuickButtonStates();
                    loadData();
                }
            });
        });

        // Daily navigation listeners
        if (prevDayBtn) {
            prevDayBtn.addEventListener("click", () => {
                currentMode = "date";
                currentWindow = "day";
                const today = localToday();
                const cur = (datePicker && datePicker.value) || currentDate || today;
                let target = addDays(cur, -1);
                if (datePicker && datePicker.min && target < datePicker.min) {
                    target = datePicker.min;
                }
                currentDate = target;
                if (datePicker) datePicker.value = currentDate;
                updateQuickButtonStates();
                loadData();
            });
        }

        if (todayBtn) {
            todayBtn.addEventListener("click", () => {
                currentMode = "date";
                currentWindow = "day";
                currentDate = localToday();
                if (datePicker) datePicker.value = currentDate;
                updateQuickButtonStates();
                loadData();
            });
        }

        if (nextDayBtn) {
            nextDayBtn.addEventListener("click", () => {
                const today = localToday();
                const cur = (datePicker && datePicker.value) || currentDate || today;
                if (cur >= today) return;
                currentMode = "date";
                currentWindow = "day";
                let target = addDays(cur, 1);
                if (target > today) target = today;
                currentDate = target;
                if (datePicker) datePicker.value = currentDate;
                updateQuickButtonStates();
                loadData();
            });
        }

        if (datePicker) {
            datePicker.addEventListener("change", () => {
                currentMode = "date";
                currentWindow = "day";
                const today = localToday();
                if (datePicker.value > today) {
                    datePicker.value = today;
                } else if (datePicker.min && datePicker.value < datePicker.min) {
                    datePicker.value = datePicker.min;
                }
                currentDate = datePicker.value || today;
                updateQuickButtonStates();
                loadData();
            });
        }

        if (clientFilter) {
            clientFilter.addEventListener("change", () => {
                currentClientIp = clientFilter.value;
                syncQuickDeviceButtons();
                loadData();
            });
        }

        if (domainFilter) {
            domainFilter.addEventListener("input", applyClientSearch);
        }

        if (refreshBtn) {
            refreshBtn.addEventListener("click", loadData);
        }
    }

    // Initialize state immediately so controls (including datePicker) are populated without waiting
    function initFailures(shouldLoadData = false) {
        setupElements();
        if (!listenersBound && screen) {
            bindEventListeners();
            listenersBound = true;
        }
        initDateConstraints();
        updateQuickButtonStates();
        loadClients();
        if (shouldLoadData || (screen && !screen.classList.contains("hidden"))) {
            loadData();
        }
    }

    if (document.readyState !== "loading") {
        initFailures();
    } else {
        document.addEventListener("DOMContentLoaded", () => initFailures());
    }

    document.addEventListener("failures-open", () => {
        initFailures(true);
    });
})();
