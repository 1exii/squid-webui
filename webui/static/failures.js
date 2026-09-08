(() => {
    let screen = null;
    let quickButtons = [];
    let prevDayBtn = null;
    let todayBtn = null;
    let nextDayBtn = null;
    let datePicker = null;
    let clientFilter = null;
    let typeFilter = null;
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
    let currentFailureType = "";
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
        let totalFailures = 0;

        events.forEach(e => {
            const count = e.count || 1;
            totalFailures += count;
            const dom = e.domain || "";
            const cat = e.category || "Unknown";

            domainCounts[dom] = (domainCounts[dom] || 0) + count;
            if (!domainCategories[dom]) domainCategories[dom] = {};
            domainCategories[dom][cat] = (domainCategories[dom][cat] || 0) + count;
            categoryCounts[cat] = (categoryCounts[cat] || 0) + count;

            if (e.clients && Array.isArray(e.clients) && e.clients.length > 0) {
                e.clients.forEach(c => {
                    if (c.client_ip) {
                        clientCounts[c.client_ip] = (clientCounts[c.client_ip] || 0) + (c.count || 1);
                    }
                });
            } else if (e.client_ip) {
                clientCounts[e.client_ip] = (clientCounts[e.client_ip] || 0) + count;
            }
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
            total_failures: totalFailures,
            unique_domains: Object.keys(domainCounts).length,
            unique_clients: Object.keys(clientCounts).length,
            category_counts: categoryCounts,
            top_domains: topDomains,
        };
    }

    function renderCurrentView() {
        if (!currentFullDataset) return;
        const allEvents = currentFullDataset.events || [];
        let filteredEvents = allEvents;

        if (currentClientIp) {
            const clientFiltered = [];
            filteredEvents.forEach(e => {
                if (e.clients && Array.isArray(e.clients)) {
                    const match = e.clients.find(c => c.client_ip === currentClientIp);
                    if (match) {
                        clientFiltered.push({
                            ...e,
                            count: match.count || 1,
                            client_ip: currentClientIp,
                            client_name: match.client_name || currentClientIp,
                            clients: [match],
                            client_ips: [currentClientIp],
                        });
                    }
                } else if (e.client_ip === currentClientIp || (e.client_ips && e.client_ips.includes(currentClientIp))) {
                    clientFiltered.push(e);
                }
            });
            filteredEvents = clientFiltered;
        }

        if (currentFailureType) {
            filteredEvents = filteredEvents.filter(e => (e.category || "Unknown") === currentFailureType);
        }

        const isFiltered = Boolean(currentClientIp || currentFailureType);
        const filteredSummary = isFiltered ? computeFilteredSummary(filteredEvents) : currentFullDataset.summary;

        renderData({
            ...currentFullDataset,
            summary: filteredSummary,
            events: filteredEvents,
        }, false);
    }

    function selectFailureType(type) {
        currentFailureType = type || "";
        if (typeFilter) {
            typeFilter.value = currentFailureType;
        }
        syncCategoryPills();
        renderCurrentView();
    }

    function syncCategoryPills() {
        if (!categoryPills) return;
        const pills = categoryPills.querySelectorAll(".category-pill");
        pills.forEach(pill => {
            pill.classList.toggle("active", (pill.dataset.category || "") === currentFailureType);
        });
    }

    function populateFailureTypeFilter(categories) {
        if (!typeFilter) return;
        typeFilter.replaceChildren();

        const allOpt = document.createElement("option");
        allOpt.value = "";
        allOpt.textContent = "All Failure Types";
        typeFilter.appendChild(allOpt);

        if (!categories || Object.keys(categories).length === 0) {
            currentFailureType = "";
            return;
        }

        let foundCurrent = false;
        Object.entries(categories)
            .sort((a, b) => b[1] - a[1])
            .forEach(([cat, count]) => {
                const opt = document.createElement("option");
                opt.value = cat;
                opt.textContent = `${cat} (${count.toLocaleString()})`;
                if (cat === currentFailureType) {
                    opt.selected = true;
                    foundCurrent = true;
                }
                typeFilter.appendChild(opt);
            });

        if (!foundCurrent && currentFailureType) {
            currentFailureType = "";
            typeFilter.value = "";
        } else {
            typeFilter.value = currentFailureType;
        }
        syncCategoryPills();
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

    function fitQuickDeviceButtons() {
        if (!quickDevicesContainer) return;
        if (typeof window.fitQuickDeviceButtons === "function") {
            window.fitQuickDeviceButtons(quickDevicesContainer);
            return;
        }
        const buttons = Array.from(quickDevicesContainer.querySelectorAll(".top8-btn"));
        buttons.forEach(button => { button.hidden = false; });
        if (!buttons.length || quickDevicesContainer.getBoundingClientRect().width === 0) return;

        const firstRowTop = buttons[0].offsetTop;
        const firstWrappedIndex = buttons.findIndex(button => button.offsetTop > firstRowTop + 1);
        const visibleCount = firstWrappedIndex === -1 ? buttons.length : firstWrappedIndex;
        buttons.forEach((button, index) => { button.hidden = index >= visibleCount; });
        quickDevicesContainer.dataset.visibleCount = String(visibleCount);
    }

    function observeQuickDeviceButtons() {
        if (!quickDevicesContainer) return;
        if (typeof window.observeQuickDeviceButtons === "function") {
            window.observeQuickDeviceButtons(quickDevicesContainer);
            return;
        }
        let previousWidth = -1;
        if ("ResizeObserver" in window) {
            const observer = new ResizeObserver(entries => {
                const width = entries[0]?.contentRect.width ?? quickDevicesContainer.getBoundingClientRect().width;
                if (Math.abs(width - previousWidth) < 1) return;
                previousWidth = width;
                fitQuickDeviceButtons();
            });
            observer.observe(quickDevicesContainer);
        } else {
            window.addEventListener("resize", () => fitQuickDeviceButtons());
        }
    }

    function renderQuickDeviceButtons(devices) {
        if (!quickDevicesContainer) return;
        quickDevicesContainer.replaceChildren();

        const allBtn = document.createElement("button");
        allBtn.type = "button";
        allBtn.className = `top8-btn ${currentClientIp === "" ? "active" : ""}`;
        allBtn.dataset.ip = "";
        allBtn.textContent = "🌐 All";
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
                if (currentClientIp === dev.ip) {
                    selectClient("");
                } else {
                    selectClient(dev.ip);
                }
            });
            quickDevicesContainer.appendChild(btn);
        });
        requestAnimationFrame(() => fitQuickDeviceButtons());
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

        Object.entries(categories)
            .sort((a, b) => b[1] - a[1])
            .forEach(([cat, count]) => {
                const pill = document.createElement("span");
                pill.className = `category-pill ${cat === currentFailureType ? "active" : ""}`;
                pill.dataset.category = cat;
                pill.textContent = `${cat}: ${count.toLocaleString()}`;
                pill.title = `Click to filter by ${cat}`;
                pill.addEventListener("click", () => {
                    if (currentFailureType === cat) {
                        selectFailureType("");
                    } else {
                        selectFailureType(cat);
                    }
                });
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
        const count = event.count || 1;
        const parts = [
            "### Squid Proxy Access Failure Report",
        ];
        const firstSeen = event.first_seen || event.datetime_local || "";
        const lastSeen = event.last_seen || event.datetime_local || "";

        if (count > 1) {
            parts.push(`- **Frequency / Repetition**: Repeated **${count.toLocaleString()} times** between ${firstSeen} and ${lastSeen}`);
            parts.push(`- **Last Occurrence**: ${lastSeen} (epoch: ${event.timestamp || ""})`);
            parts.push(`- **First Occurrence**: ${firstSeen}`);
        } else {
            parts.push(`- **Timestamp**: ${lastSeen} (epoch: ${event.timestamp || ""})`);
        }

        if (event.clients && event.clients.length > 1) {
            const devDesc = event.clients.map(c => `${c.client_name} (${c.client_ip}, x${(c.count || 1).toLocaleString()})`).join(", ");
            parts.push(`- **Affected Client Devices**: ${devDesc}`);
        } else {
            parts.push(`- **Client Device**: ${event.client_name || event.client_ip || ""} (${event.client_ip || ""})`);
        }

        parts.push(
            `- **Target Domain**: ${event.domain || ""}`,
            `- **Destination**: ${event.method || ""} ${event.url || ""}`,
            `- **Squid Result Code**: ${event.result || ""} (HTTP Status: ${event.status || ""})`,
            `- **Error Category**: ${event.category || ""}`,
            `- **Preliminary Diagnostic**: ${event.explanation || ""}`,
            ""
        );

        const rawLogs = event.raw_logs || (event.raw_log ? [event.raw_log] : []);
        if (count > 1) {
            parts.push(`#### Raw Squid Access Log Line(s) (Repeated ${count.toLocaleString()} times between ${firstSeen} and ${lastSeen}):`);
            parts.push("```text");
            if (rawLogs.length > 5) {
                parts.push(...rawLogs.slice(0, 3));
                parts.push(`... [Repeated ${count.toLocaleString()} times total; showing first 3 and last 2 entries] ...`);
                parts.push(...rawLogs.slice(-2));
            } else if (rawLogs.length > 0) {
                parts.push(...rawLogs);
            } else if (event.raw_log) {
                parts.push(event.raw_log);
            }
            parts.push("```", "");
            parts.push("#### Diagnostic Prompt:");
            parts.push(
                `This connection failure occurred repeatedly (${count.toLocaleString()} times) between ${firstSeen} and ${lastSeen}. ` +
                "Please analyze the root cause of this recurring failure in the Squid proxy environment. " +
                "Could this be caused by SSL inspection/certificate pinning, an upstream network or DNS issue, " +
                "or a Squid configuration issue? What are the specific troubleshooting steps or recommended ACL/splice fixes?"
            );
        } else {
            parts.push("#### Raw Squid Access Log Line:");
            parts.push("```text");
            parts.push(event.raw_log || "");
            parts.push("```", "");
            parts.push("#### Diagnostic Prompt:");
            parts.push(
                "Please analyze the root cause of this failure in the Squid proxy environment. " +
                "Could this be caused by SSL inspection/certificate pinning, an upstream network or DNS issue, " +
                "or a Squid configuration issue? What are the specific troubleshooting steps or recommended ACL/splice fixes?"
            );
        }
        return parts.join("\n");
    }

    function renderEventCard(event) {
        const card = document.createElement("div");
        card.className = "failure-card glass-panel";
        const clientSearchTokens = event.client_names
            ? event.client_names.join(" ")
            : (event.client_name || event.client_ip || "");
        card.dataset.domain = (event.domain || "").toLowerCase();
        card.dataset.client = clientSearchTokens.toLowerCase();
        card.dataset.explanation = (event.explanation || "").toLowerCase();

        const count = event.count || 1;
        const statusClass = getStatusClass(event.status);
        const countBadge = count > 1
            ? `<span class="failure-count-badge" title="${count.toLocaleString()} occurrences">🔁 ${count.toLocaleString()} occurrences</span>`
            : "";

        const timeHtml = (count > 1 && event.first_seen && event.last_seen && event.first_seen !== event.last_seen)
            ? `🕒 Last: ${escapeHtml(event.last_seen)} <span class="time-range-sub">(First: ${escapeHtml(event.first_seen)})</span>`
            : `🕒 ${escapeHtml(event.datetime_local || event.last_seen || "")}`;

        let deviceBadgeHtml = "";
        if (event.clients && event.clients.length > 1) {
            const clientListText = event.clients.map(c => `${escapeHtml(c.client_name || c.client_ip)} (x${c.count})`).join(", ");
            deviceBadgeHtml = `<span class="failure-device-badge clickable-filter" title="Filter by ${escapeHtml(event.client_name || event.client_ip)} (Primary of ${event.clients.length} devices)">📱 ${event.clients.length} devices: ${clientListText}</span>`;
        } else {
            deviceBadgeHtml = `<span class="failure-device-badge clickable-filter" title="Filter by ${escapeHtml(event.client_name || event.client_ip)}">${getDeviceIcon(event.client_name)} ${escapeHtml(event.client_name)} (${escapeHtml(event.client_ip)})</span>`;
        }

        const rawLogText = event.raw_log || (event.raw_logs ? event.raw_logs.join("\n") : "");
        const viewRawLabel = count > 1 ? `📄 View All Raw Logs (${count.toLocaleString()})` : "📄 View Raw Log";
        const hideRawLabel = count > 1 ? `📄 Hide Raw Logs (${count.toLocaleString()})` : "📄 Hide Raw Log";

        card.innerHTML = `
            <div class="failure-card-header">
                <div class="failure-title-group">
                    <span class="failure-domain">${escapeHtml(event.domain)}</span>
                    <span class="failure-status-badge ${statusClass}">${escapeHtml(event.result || event.status)}</span>
                    ${countBadge}
                </div>
                <div class="failure-meta">
                    <span class="failure-time">${timeHtml}</span>
                    ${deviceBadgeHtml}
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
                <button type="button" class="btn btn-sm btn-text btn-toggle-raw">${viewRawLabel}</button>
            </div>
            <pre class="raw-log-container hidden"><code>${escapeHtml(rawLogText)}</code></pre>
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
                toggleRawBtn.textContent = isHidden ? viewRawLabel : hideRawLabel;
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
        if (typeFilter && !currentFailureType) {
            typeFilter.replaceChildren();
            const defaultOpt = document.createElement("option");
            defaultOpt.value = "";
            defaultOpt.textContent = "All Failure Types";
            typeFilter.appendChild(defaultOpt);
        }

        // Clear KPI stats immediately so previous day data is never displayed while loading
        if (kpiTotal) kpiTotal.textContent = "—";
        if (kpiDomains) kpiDomains.textContent = "—";
        if (kpiClients) kpiClients.textContent = "—";
        if (kpiCategory) kpiCategory.textContent = "—";
    }

    function renderData(data, updateTypeFilter = true) {
        const summary = data.summary || {};
        loadedEvents = data.events || [];

        // Update KPI cards
        if (kpiTotal) kpiTotal.textContent = (summary.total_failures || 0).toLocaleString();
        if (kpiDomains) kpiDomains.textContent = (summary.unique_domains || 0).toLocaleString();
        if (kpiClients) kpiClients.textContent = (summary.unique_clients || 0).toLocaleString();

        const topDomain = summary.top_domains && summary.top_domains[0];
        const topCategory = currentFailureType || (topDomain ? topDomain.primary_category : (summary.category_counts && Object.keys(summary.category_counts)[0]) || "-");
        if (kpiCategory) kpiCategory.textContent = topCategory;

        // Cache badge
        if (cacheBadge) cacheBadge.classList.toggle("hidden", !data.cached);

        // Category breakdown
        renderCategoryPills(summary.category_counts);

        if (updateTypeFilter && currentFullDataset && currentFullDataset.summary) {
            populateFailureTypeFilter(currentFullDataset.summary.category_counts);
        }

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
            populateFailureTypeFilter(currentFullDataset.summary && currentFullDataset.summary.category_counts);
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
            currentFullDatasetKey = cacheKey;
            populateFailureTypeFilter(data.summary && data.summary.category_counts);
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
        typeFilter = document.getElementById("failures-type-filter");
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

        if (!quickDevicesObserved && quickDevicesContainer) {
            observeQuickDeviceButtons();
            quickDevicesObserved = true;
        }
    }

    let listenersBound = false;
    let quickDevicesObserved = false;

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

        if (typeFilter) {
            typeFilter.addEventListener("change", () => {
                selectFailureType(typeFilter.value);
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
        requestAnimationFrame(() => fitQuickDeviceButtons());
    });
})();
