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
    let currentFullDataset = null;
    let currentFullDatasetKey = "";
    const sessionDatasetCache = new Map();

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

    function computeFilteredSummary(events) {
        const domainCounts = {};
        const domainCategories = {};
        const clientCounts = {};
        const categoryCounts = {};

        events.forEach(e => {
            const dom = e.domain || "";
            const cat = e.category || "Unknown";
            const cip = e.client_ip || "";

            domainCounts[dom] = (domainCounts[dom] || 0) + 1;
            if (!domainCategories[dom]) domainCategories[dom] = {};
            domainCategories[dom][cat] = (domainCategories[dom][cat] || 0) + 1;
            clientCounts[cip] = (clientCounts[cip] || 0) + 1;
            categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
        });

        const topDomains = Object.entries(domainCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 25)
            .map(([domain, count]) => {
                const cats = Object.entries(domainCategories[domain] || {}).sort((a, b) => b[1] - a[1]);
                return {
                    domain,
                    failures: count,
                    primary_category: cats.length > 0 ? cats[0][0] : "Unknown",
                };
            });

        return {
            total_failures: events.length,
            unique_domains: Object.keys(domainCounts).length,
            unique_clients: Object.keys(clientCounts).length,
            category_counts: categoryCounts,
            top_domains: topDomains,
        };
    }

    function renderCurrentView() {
        if (!currentFullDataset) return;
        if (!currentClientIp) {
            renderData(currentFullDataset);
        } else {
            const allEvents = currentFullDataset.events || [];
            const filteredEvents = allEvents.filter(e => e.client_ip === currentClientIp);
            const filteredSummary = computeFilteredSummary(filteredEvents);
            renderData({
                ...currentFullDataset,
                summary: filteredSummary,
                events: filteredEvents,
            });
        }
    }

    function selectClient(ip) {
        currentClientIp = ip || "";
        if (clientFilter) {
            clientFilter.value = currentClientIp;
        }
        syncQuickDeviceButtons();

        const activeKey = `${currentMode}:${currentMode === "window" ? currentWindow : currentDate}`;
        if (currentFullDataset && currentFullDatasetKey === activeKey) {
            renderCurrentView();
            return;
        }

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

    async function copyTextToClipboard(text) {
        if (navigator.clipboard && window.isSecureContext) {
            try {
                await navigator.clipboard.writeText(text);
                return true;
            } catch (_) {}
        }

        // Fallback for non-secure HTTP contexts (e.g. LAN WebUI on Chrome/Ubuntu)
        let textArea = null;
        try {
            textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.position = "fixed";
            textArea.style.top = "-9999px";
            textArea.style.left = "-9999px";
            textArea.style.opacity = "0";
            textArea.setAttribute("readonly", "");
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            textArea.setSelectionRange(0, 99999);
            const successful = document.execCommand("copy");
            if (successful) return true;
        } catch (_) {
        } finally {
            if (textArea && textArea.parentNode) {
                textArea.parentNode.removeChild(textArea);
            }
        }

        // Last-resort fallback: prompt user with pre-selected text
        try {
            window.prompt("Press Ctrl+C to copy diagnostic prompt:", text);
            return true;
        } catch (_) {
            return false;
        }
    }

    function buildCopyPrompt(event) {
        if (event.copyable_prompt) return event.copyable_prompt;
        const parts = [
            "### Squid Proxy Access Failure Report",
            `- **Timestamp**: ${event.datetime_local || ""} (epoch: ${event.timestamp || ""})`,
            `- **Client Device**: ${event.client_name || event.client_ip || ""} (${event.client_ip || ""})`,
            `- **Target Domain**: ${event.domain || ""}`,
            `- **Destination**: ${event.method || ""} ${event.url || ""}`,
            `- **Squid Result Code**: ${event.result || ""} (HTTP Status: ${event.status || ""})`,
            `- **Error Category**: ${event.category || ""}`,
            `- **Preliminary Diagnostic**: ${event.explanation || ""}`,
            "",
            "#### Raw Squid Access Log Line:",
            "```text",
            event.raw_log || "",
            "```",
            "",
            "#### Diagnostic Prompt:",
            "Please analyze the root cause of this failure in the Squid proxy environment. " +
            "Could this be caused by SSL inspection/certificate pinning, an upstream network or DNS issue, " +
            "or a Squid configuration issue? What are the specific troubleshooting steps or recommended ACL/splice fixes?"
        ];
        return parts.join("\n");
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
                const prompt = buildCopyPrompt(event);
                const copied = await copyTextToClipboard(prompt);
                if (copied) {
                    const originalText = copyBtn.textContent;
                    copyBtn.textContent = "✅ Copied to clipboard!";
                    copyBtn.classList.add("btn-success");
                    setTimeout(() => {
                        copyBtn.textContent = originalText;
                        copyBtn.classList.remove("btn-success");
                    }, 2000);
                } else {
                    alert("Failed to copy to clipboard. Please view raw log to copy manually.");
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

    let currentRenderBatch = 50;

    function renderEventList(events) {
        if (!failuresList) return;
        failuresList.replaceChildren();

        const query = (domainFilter && domainFilter.value || "").trim().toLowerCase();
        let matched = events || [];
        if (query) {
            matched = matched.filter(e => {
                const dom = (e.domain || "").toLowerCase();
                const cl = (e.client_name || e.client_ip || "").toLowerCase();
                const exp = (e.explanation || "").toLowerCase();
                return dom.includes(query) || cl.includes(query) || exp.includes(query);
            });
        }

        if (matched.length === 0) {
            if (emptyState) {
                emptyState.classList.remove("hidden");
                const p = emptyState.querySelector("p");
                if (p) {
                    p.innerHTML = query
                        ? `🔍 No failures matching <strong>${escapeHtml(query)}</strong>.`
                        : "🎉 <strong>No non-policy connection failures detected</strong> in this time period.";
                }
            }
            return;
        }

        if (emptyState) emptyState.classList.add("hidden");

        const toRender = matched.slice(0, currentRenderBatch);
        const fragment = document.createDocumentFragment();
        toRender.forEach(evt => {
            fragment.appendChild(renderEventCard(evt));
        });
        failuresList.appendChild(fragment);

        if (matched.length > toRender.length) {
            const paginationBar = document.createElement("div");
            paginationBar.className = "failure-pagination-bar";
            paginationBar.style.display = "flex";
            paginationBar.style.justifyContent = "center";
            paginationBar.style.alignItems = "center";
            paginationBar.style.gap = "12px";
            paginationBar.style.padding = "24px 0";

            const countLabel = document.createElement("span");
            countLabel.style.fontSize = "0.9rem";
            countLabel.style.color = "var(--text-muted, #888)";
            countLabel.textContent = `Showing ${toRender.length} of ${matched.length} failures`;

            const loadMoreBtn = document.createElement("button");
            loadMoreBtn.type = "button";
            loadMoreBtn.className = "btn btn-secondary";
            loadMoreBtn.textContent = "⬇️ Load 50 More";
            loadMoreBtn.addEventListener("click", () => {
                currentRenderBatch += 50;
                renderEventList(events);
            });

            const loadAllBtn = document.createElement("button");
            loadAllBtn.type = "button";
            loadAllBtn.className = "btn btn-text";
            loadAllBtn.textContent = `Load All (${matched.length})`;
            loadAllBtn.addEventListener("click", () => {
                currentRenderBatch = matched.length;
                renderEventList(events);
            });

            paginationBar.appendChild(countLabel);
            paginationBar.appendChild(loadMoreBtn);
            paginationBar.appendChild(loadAllBtn);
            failuresList.appendChild(paginationBar);
        }
    }

    function applyClientSearch() {
        currentRenderBatch = 50;
        renderEventList(loadedEvents);
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

    function renderData(data) {
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

        currentRenderBatch = 50;
        renderEventList(loadedEvents);
    }

    async function loadData(forceRefresh = false) {
        const today = localToday();
        const cacheKey = `${currentMode}:${currentMode === "window" ? currentWindow : (currentDate || today)}`;

        // If already cached in this session, display immediately without network latency or spinners
        if (!forceRefresh && sessionDatasetCache.has(cacheKey)) {
            if (currentFetchController) {
                currentFetchController.abort();
                currentFetchController = null;
            }
            if (loadingIndicator) loadingIndicator.classList.add("hidden");
            currentFullDataset = sessionDatasetCache.get(cacheKey);
            currentFullDatasetKey = cacheKey;
            renderCurrentView();
            return;
        }

        if (currentFetchController) {
            currentFetchController.abort();
        }
        currentFetchController = new AbortController();

        clearCurrentStatsAndList();

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
        if (forceRefresh) {
            url += "&refresh=1";
        }

        try {
            const res = await fetch(url, { signal: currentFetchController.signal });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.error || "Failed to load failure data");
            }
            const data = await res.json();
            sessionDatasetCache.set(cacheKey, data);
            currentFullDataset = data;
            currentFullDatasetKey = `${currentMode}:${currentMode === "window" ? currentWindow : currentDate}`;
            currentFullDatasetKey = cacheKey;
            renderCurrentView();
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
                currentFullDataset = null;
                currentFullDatasetKey = "";
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
                currentFullDataset = null;
                currentFullDatasetKey = "";
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
                currentFullDataset = null;
                currentFullDatasetKey = "";
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
                currentFullDataset = null;
                currentFullDatasetKey = "";
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
                currentFullDataset = null;
                currentFullDatasetKey = "";
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
                selectClient(clientFilter.value);
            });
        }

        if (domainFilter) {
            domainFilter.addEventListener("input", applyClientSearch);
        }

        if (refreshBtn) {
            refreshBtn.addEventListener("click", () => {
                currentFullDataset = null;
                currentFullDatasetKey = "";
                const today = localToday();
                const cacheKey = `${currentMode}:${currentMode === "window" ? currentWindow : (currentDate || today)}`;
                sessionDatasetCache.delete(cacheKey);
                loadData(true);
            });
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
