(() => {
    const panel = document.getElementById('tls-exceptions-panel');
    if (!panel) return;
    const rows = document.getElementById('tls-exception-rows');
    const status = document.getElementById('tls-exception-status');
    const save = document.getElementById('tls-exception-save');
    let loaded = false;
    function add(entry = {domain: '', destination_networks: [], enabled: true}) {
        const row = document.createElement('div');
        row.className = 'tls-exception-row';
        const field = (text, control) => {
            const label = document.createElement('label');
            label.textContent = text;
            label.append(control);
            row.append(label);
        };
        const domain = document.createElement('input');
        domain.type = 'text'; domain.value = entry.domain;
        domain.className = 'tls-domain'; domain.placeholder = 'vivox.com';
        field('Domain', domain);
        const networks = document.createElement('textarea');
        networks.className = 'tls-networks'; networks.rows = 2;
        networks.value = entry.destination_networks.join('\n');
        networks.placeholder = 'One public CIDR per line';
        field('Destination networks (optional for explicit proxy only)', networks);
        const enabled = document.createElement('input');
        enabled.type = 'checkbox'; enabled.checked = entry.enabled; enabled.className = 'tls-enabled';
        field('Enabled', enabled);
        const remove = document.createElement('button');
        remove.type = 'button'; remove.className = 'btn btn-secondary'; remove.textContent = 'Delete';
        remove.addEventListener('click', () => row.remove());
        row.append(remove); rows.append(row);
    }
    async function api(options) {
        const response = await fetch('/api/tls-exceptions', options);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || data.message || 'Request failed');
        return data;
    }
    async function load() {
        save.disabled = true;
        try {
            const data = await api();
            rows.replaceChildren(); data.entries.forEach(add); loaded = true;
            status.textContent = 'Saved entries loaded.';
        } catch (error) { status.textContent = error.message; }
        finally { save.disabled = !loaded; }
    }
    save.disabled = true;
    document.addEventListener('tls-exceptions-open', () => { if (!loaded) load(); });
    document.getElementById('tls-exception-reload').addEventListener('click', load);
    document.getElementById('tls-exception-add').addEventListener('click', () => { if (loaded) add(); });
    save.addEventListener('click', async () => {
        const entries = Array.from(rows.children, row => ({
            domain: row.querySelector('.tls-domain').value,
            destination_networks: row.querySelector('.tls-networks').value.split(/[\s,]+/).filter(Boolean),
            enabled: row.querySelector('.tls-enabled').checked
        }));
        save.disabled = true; status.textContent = 'Validating and applying…';
        try {
            const data = await api({method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({entries})});
            rows.replaceChildren(); data.entries.forEach(add); status.textContent = data.message;
        } catch (error) { status.textContent = error.message; }
        finally { save.disabled = false; }
    });
})();
