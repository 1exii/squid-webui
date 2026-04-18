#!/usr/bin/env python3
import os
import sys
import re

def process_blocklists(blocklist_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    bump_domains = set()
    domain_blocklist = set()
    url_rules = []

    if not os.path.exists(blocklist_dir):
        print(f"[process_blocklists] WARNING: Directory '{blocklist_dir}' does not exist.")
        return

    rule_idx = 0
    for filename in sorted(os.listdir(blocklist_dir)):
        if not filename.endswith(".txt"):
            continue

        filepath = os.path.join(blocklist_dir, filename)
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if "/" in line:
                        # Entry contains URL path (e.g. steamcommunity.com/market or roblox.com/upgrades/robux)
                        parts = line.split("/", 1)
                        raw_domain = parts[0].strip()
                        path = "/" + parts[1].strip()

                        clean_domain = raw_domain.lstrip(".")
                        if not clean_domain:
                            continue

                        # Domain requires SSL Bumping for deep URL inspection
                        bump_domains.add(clean_domain)
                        bump_domains.add(f".{clean_domain}")

                        rule_idx += 1
                        dom_acl = f"acl path_dom_{rule_idx} dstdomain {clean_domain} .{clean_domain}"
                        path_acl = f"acl path_url_{rule_idx} urlpath_regex -i ^{re.escape(path)}"
                        deny_rule = f"http_access deny path_dom_{rule_idx} path_url_{rule_idx}"
                        url_rules.extend([dom_acl, path_acl, deny_rule, ""])
                    else:
                        # Plain domain entry (e.g. .facebook.com or pornhub.com)
                        domain_blocklist.add(line)
        except Exception as e:
            print(f"[process_blocklists] Error processing {filepath}: {e}")

    # Write bump_domains.acl
    bump_file = os.path.join(output_dir, "bump_domains.acl")
    with open(bump_file, "w", encoding="utf-8") as f:
        f.write("# Auto-generated: Domains requiring SSL Bumping for deep URL inspection\n")
        for domain in sorted(bump_domains):
            f.write(f"{domain}\n")
    print(f"[process_blocklists] Wrote {len(bump_domains)} domains to {bump_file}")

    # Write domain_blocklists.acl
    domain_file = os.path.join(output_dir, "domain_blocklists.acl")
    with open(domain_file, "w", encoding="utf-8") as f:
        f.write("# Auto-generated: Plain domain blocklists (blocked at SNI without SSL Bumping)\n")
        for domain in sorted(domain_blocklist):
            f.write(f"{domain}\n")
    print(f"[process_blocklists] Wrote {len(domain_blocklist)} domains to {domain_file}")

    # Write url_blocklists.acl
    url_file = os.path.join(output_dir, "url_blocklists.acl")
    with open(url_file, "w", encoding="utf-8") as f:
        f.write("# Auto-generated: Path-specific URL blocklist rules (requires SSL Bumping)\n")
        f.write("\n".join(url_rules) + "\n")
    print(f"[process_blocklists] Wrote {rule_idx} URL path rules to {url_file}")

if __name__ == "__main__":
    bl_dir = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SQUID_BLOCKLIST_DIR", "/etc/squid/block-lists")
    out_dir = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("SQUID_CONFIG_DIR", "/etc/squid/configs")

    # Fallback to local directory if path does not exist on host runner
    if not os.path.exists(bl_dir):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_squid = os.path.abspath(os.path.join(script_dir, ".."))
        local_bl = os.path.join(repo_squid, "block-lists")
        local_out = os.path.join(repo_squid, "configs")
        if os.path.exists(local_bl):
            bl_dir = local_bl
            out_dir = local_out

    print(f"[process_blocklists] Processing blocklists from: {bl_dir} -> {out_dir}")
    process_blocklists(bl_dir, out_dir)
