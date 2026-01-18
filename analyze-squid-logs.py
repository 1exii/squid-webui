#!/usr/bin/env python3
"""
Squid Access Log Analyzer & Per-Host Web Activity Report Generator

Generates a standalone, interactive HTML report (`host-domains-report.html`)
listing all websites and domain names visited by each local host IP address,
mapping IPs to hostnames via proxy-hosts.conf. Also embeds cross-navigation links
to the GoAccess report (squid-report.html).
"""

import os
import sys
import argparse
import datetime
from collections import defaultdict
from urllib.parse import urlparse

def parse_proxy_hosts(hosts_file):
    mapping = {}
    if os.path.exists(hosts_file):
        with open(hosts_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    mapping[parts[0]] = parts[1]
    return mapping

def format_bytes(b):
    if b >= 1073741824:
        return f"{b / 1073741824:.2f} GB"
    if b >= 1048576:
        return f"{b / 1048576:.1f} MB"
    if b >= 1024:
        return f"{b / 1024:.1f} KB"
    return f"{b} B"

def analyze_logs(log_file, hosts_file):
    ip_hostname_map = parse_proxy_hosts(hosts_file)
    host_stats = defaultdict(lambda: defaultdict(lambda: {'hits': 0, 'bytes': 0, 'last_ts': 0}))

    if not os.path.exists(log_file):
        print(f"[!] Log file not found: {log_file}")
        sys.exit(1)

    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 7:
                try:
                    raw_ts = float(parts[0])
                except ValueError:
                    continue
                client_ip = parts[2]
                try:
                    bytes_sent = int(parts[4])
                except ValueError:
                    bytes_sent = 0
                url = parts[6]

                if url.startswith('http://') or url.startswith('https://'):
                    domain = urlparse(url).netloc
                else:
                    domain = url.split(':')[0]
                if not domain:
                    domain = '-'

                entry = host_stats[client_ip][domain]
                entry['hits'] += 1
                entry['bytes'] += bytes_sent
                if raw_ts > entry['last_ts']:
                    entry['last_ts'] = raw_ts

    return host_stats, ip_hostname_map

def generate_host_domains_html(host_stats, ip_hostname_map, output_file):
    total_hosts = len([ip for ip in host_stats if ip != '-'])
    global_hits = sum(sum(d['hits'] for d in domains.values()) for ip, domains in host_stats.items() if ip != '-')
    global_bytes = sum(sum(d['bytes'] for d in domains.values()) for ip, domains in host_stats.items() if ip != '-')

    # Build Host Tabs & Cards HTML
    tab_buttons = []
    host_sections = []

    sorted_ips = sorted([ip for ip in host_stats.keys() if ip != '-'])

    # All Hosts Button
    tab_buttons.append('<button class="tab-btn active" onclick="showTab(\'all\', this)">All Hosts Overview</button>')

    for idx, ip in enumerate(sorted_ips):
        hostname = ip_hostname_map.get(ip, 'Unknown Host')
        display_title = f"{hostname} ({ip})"
        tab_buttons.append(f'<button class="tab-btn" onclick="showTab(\'host-{idx}\', this)">💻 {display_title}</button>')

        domains = host_stats[ip]
        host_hits = sum(d['hits'] for d in domains.values())
        host_bytes = sum(d['bytes'] for d in domains.values())

        rows = []
        for dom, data in sorted(domains.items(), key=lambda x: x[1]['hits'], reverse=True):
            dt = datetime.datetime.fromtimestamp(data['last_ts']).strftime('%Y-%m-%d %H:%M:%S')
            rows.append(f'''
            <tr class="domain-row" data-domain="{dom.lower()}">
                <td class="domain-name"><a href="https://{dom}" target="_blank" rel="noopener">{dom}</a></td>
                <td class="num">{data['hits']:,}</td>
                <td class="num">{format_bytes(data['bytes'])}</td>
                <td class="num time-cell">{dt}</td>
            </tr>''')

        host_sections.append(f'''
        <div id="host-{idx}" class="host-card tab-content show">
            <div class="host-header">
                <div>
                    <h2>💻 {hostname} <span class="ip-badge">{ip}</span></h2>
                    <span class="subtext">{len(domains)} unique websites visited</span>
                </div>
                <div class="host-meta-pills">
                    <span class="pill">Requests: <strong>{host_hits:,}</strong></span>
                    <span class="pill">Bandwidth: <strong>{format_bytes(host_bytes)}</strong></span>
                </div>
            </div>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Website / Domain Name</th>
                            <th class="num">Requests / Hits</th>
                            <th class="num">Data Transferred</th>
                            <th class="num">Last Active Time</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>''')

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Per-Host Web Browsing Activity Report</title>
<style>
    :root {{
        --bg-color: #0f172a;
        --card-bg: #1e293b;
        --card-header: #334155;
        --text-color: #f8fafc;
        --text-muted: #94a3b8;
        --primary: #3b82f6;
        --primary-hover: #2563eb;
        --accent: #38bdf8;
        --border-color: #475569;
        --table-hover: #334155;
    }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        background-color: var(--bg-color);
        color: var(--text-color);
        margin: 0;
        padding: 24px;
        line-height: 1.5;
    }}
    .container {{
        max-width: 1200px;
        margin: 0 auto;
    }}
    .header-bar {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: linear-gradient(135deg, #1e3a8a 0%, #0f172a 100%);
        padding: 24px;
        border-radius: 12px;
        border: 1px solid var(--border-color);
        margin-bottom: 24px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }}
    .header-bar h1 {{
        margin: 0 0 6px 0;
        font-size: 24px;
        color: #ffffff;
    }}
    .header-bar p {{
        margin: 0;
        color: var(--text-muted);
        font-size: 14px;
    }}
    .nav-btn {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background-color: var(--primary);
        color: #ffffff;
        padding: 10px 18px;
        border-radius: 8px;
        text-decoration: none;
        font-weight: 600;
        font-size: 14px;
        transition: background-color 0.2s;
    }}
    .nav-btn:hover {{
        background-color: var(--primary-hover);
    }}
    .stats-row {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
    }}
    .stat-card {{
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        padding: 18px;
        border-radius: 10px;
    }}
    .stat-card .label {{
        font-size: 13px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}
    .stat-card .value {{
        font-size: 26px;
        font-weight: 700;
        color: var(--accent);
        margin-top: 4px;
    }}
    .controls-bar {{
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
    }}
    .tab-bar {{
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
    }}
    .tab-btn {{
        background: var(--card-bg);
        color: var(--text-muted);
        border: 1px solid var(--border-color);
        padding: 8px 16px;
        border-radius: 6px;
        cursor: pointer;
        font-size: 13.5px;
        font-weight: 500;
        transition: all 0.2s;
    }}
    .tab-btn:hover {{
        color: #ffffff;
        background: var(--card-header);
    }}
    .tab-btn.active {{
        background: var(--primary);
        color: #ffffff;
        border-color: var(--primary);
    }}
    .search-box {{
        padding: 9px 14px;
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        color: #ffffff;
        border-radius: 6px;
        font-size: 14px;
        width: 260px;
        outline: none;
    }}
    .search-box:focus {{
        border-color: var(--primary);
    }}
    .host-card {{
        background: var(--card-bg);
        border: 1px solid var(--border-color);
        border-radius: 10px;
        margin-bottom: 24px;
        overflow: hidden;
    }}
    .host-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 16px 20px;
        background: var(--card-header);
        border-bottom: 1px solid var(--border-color);
    }}
    .host-header h2 {{
        margin: 0;
        font-size: 18px;
        color: #ffffff;
    }}
    .ip-badge {{
        font-size: 13px;
        font-weight: normal;
        background: #0f172a;
        color: var(--accent);
        padding: 3px 8px;
        border-radius: 4px;
        margin-left: 8px;
    }}
    .subtext {{
        font-size: 13px;
        color: var(--text-muted);
        display: block;
        margin-top: 2px;
    }}
    .host-meta-pills {{
        display: flex;
        gap: 12px;
    }}
    .pill {{
        background: #0f172a;
        padding: 6px 12px;
        border-radius: 6px;
        font-size: 13px;
        color: var(--text-muted);
        border: 1px solid var(--border-color);
    }}
    .pill strong {{
        color: var(--text-color);
    }}
    .table-container {{
        overflow-x: auto;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 13.5px;
    }}
    th {{
        text-align: left;
        padding: 10px 20px;
        background: #0f172a;
        color: var(--text-muted);
        font-weight: 600;
        border-bottom: 1px solid var(--border-color);
    }}
    td {{
        padding: 10px 20px;
        border-bottom: 1px solid var(--border-color);
    }}
    tr:last-child td {{
        border-bottom: none;
    }}
    tr:hover {{
        background-color: var(--table-hover);
    }}
    td.domain-name a {{
        color: var(--accent);
        text-decoration: none;
        font-weight: 500;
    }}
    td.domain-name a:hover {{
        text-decoration: underline;
    }}
    td.num {{
        text-align: right;
        font-family: 'Consolas', monospace;
    }}
    td.time-cell {{
        color: var(--text-muted);
    }}
    .tab-content {{
        display: none;
    }}
    .tab-content.show {{
        display: block;
    }}
</style>
</head>
<body>

<div class="container">
    <div class="header-bar">
        <div>
            <h1>🌐 Per-Host Web Browsing Activity Report</h1>
            <p>Detailed list of websites and domain names visited by each local host IP address</p>
        </div>
        <a href="squid-report.html" class="nav-btn">📊 Open GoAccess Global Dashboard &rarr;</a>
    </div>

    <div class="stats-row">
        <div class="stat-card">
            <div class="label">Total Local Hosts</div>
            <div class="value">{total_hosts}</div>
        </div>
        <div class="stat-card">
            <div class="label">Total Requests Captured</div>
            <div class="value">{global_hits:,}</div>
        </div>
        <div class="stat-card">
            <div class="label">Total Data Transferred</div>
            <div class="value">{format_bytes(global_bytes)}</div>
        </div>
    </div>

    <div class="controls-bar">
        <div class="tab-bar">
            {''.join(tab_buttons)}
        </div>
        <input type="text" id="domainSearch" class="search-box" placeholder="🔍 Search domain name..." onkeyup="filterDomains()">
    </div>

    <div id="host-cards-container">
        {''.join(host_sections)}
    </div>
</div>

<script>
function showTab(tabId, btn) {{
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    const cards = document.querySelectorAll('.host-card');
    if (tabId === 'all') {{
        cards.forEach(c => c.classList.add('show'));
    }} else {{
        cards.forEach(c => {{
            if (c.id === tabId) {{
                c.classList.add('show');
            }} else {{
                c.classList.remove('show');
            }}
        }});
    }}
}}

function filterDomains() {{
    const query = document.getElementById('domainSearch').value.toLowerCase();
    const rows = document.querySelectorAll('.domain-row');

    rows.forEach(row => {{
        const domain = row.getAttribute('data-domain');
        if (domain.includes(query)) {{
            row.style.display = '';
        }} else {{
            row.style.display = 'none';
        }}
    }});
}}
</script>

</body>
</html>'''

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"  [+] Per-Host Web Activity Report generated: {output_file}")

def add_nav_link_to_goaccess(goaccess_html, host_report_rel_path="host-domains-report.html"):
    if not os.path.exists(goaccess_html):
        return

    with open(goaccess_html, 'r', encoding='utf-8') as f:
        content = f.read()

    nav_banner = f'''
    <div style="background: linear-gradient(135deg, #1e3a8a 0%, #0f172a 100%); padding: 12px 20px; color: #fff; display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #3b82f6; font-family: sans-serif;">
        <span style="font-weight: bold; font-size: 15px;">📊 GoAccess Global Analytics Dashboard</span>
        <a href="{host_report_rel_path}" style="background: #3b82f6; color: #fff; padding: 8px 16px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 13.5px; transition: background 0.2s;">
            🌐 Switch to Per-Host Web Activity Report &rarr;
        </a>
    </div>
    '''

    if 'Switch to Per-Host Web Activity Report' not in content:
        if '<body' in content:
            content = content.replace('<body>', '<body>\n' + nav_banner, 1)
        with open(goaccess_html, 'w', encoding='utf-8') as f:
            f.write(content)

def main():
    parser = argparse.ArgumentParser(description="Squid Access Log Analyzer")
    parser.add_argument("--log", required=True, help="Path to access.log")
    parser.add_argument("--hosts-conf", required=True, help="Path to proxy-hosts.conf")
    parser.add_argument("--out-host-report", required=True, help="Path for host-domains-report.html")
    parser.add_argument("--out-goaccess-report", required=False, help="Path for squid-report.html (GoAccess)")

    args = parser.parse_args()

    host_stats, ip_hostname_map = analyze_logs(args.log, args.hosts_conf)
    generate_host_domains_html(host_stats, ip_hostname_map, args.out_host_report)

    if args.out_goaccess_report:
        add_nav_link_to_goaccess(args.out_goaccess_report, os.path.basename(args.out_host_report))

if __name__ == "__main__":
    main()
