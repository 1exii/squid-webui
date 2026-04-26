#!/usr/bin/env python3
import os
import sys
import re

def deduplicate_domains(domains):
    """
    Deduplicates a collection of domain strings for Squid dstdomain ACLs.

    Squid dstdomain matching rules:
    - '.example.com' matches 'example.com' and all subdomains ('*.example.com').
    - 'example.com' matches ONLY exact 'example.com'.

    Subsumption / Duplication rules:
    1. If '.example.com' exists, 'example.com' is redundant and causes Squid duplicate domain errors/crashes.
    2. If '.example.com' exists, any '.sub.example.com' or 'sub.example.com' is subsumed and redundant.
    3. Exact string duplicates are removed.
    """
    cleaned = set()
    for d in domains:
        d = d.strip()
        if d:
            cleaned.add(d)

    wildcard_bases = {}
    for d in cleaned:
        if d.startswith("."):
            base = d.lstrip(".")
            if base:
                wildcard_bases[d] = base

    result = set()
    for d in cleaned:
        if d.startswith("."):
            base = d.lstrip(".")
            subsumed = False
            for w_domain, w_base in wildcard_bases.items():
                if w_domain != d:
                    if base == w_base or base.endswith("." + w_base):
                        if len(w_base) < len(base) or (len(w_base) == len(base) and w_domain < d):
                            subsumed = True
                            break
            if not subsumed:
                result.add(d)
        else:
            subsumed = False
            for w_domain, w_base in wildcard_bases.items():
                if d == w_base or d.endswith("." + w_base):
                    subsumed = True
                    break
            if not subsumed:
                result.add(d)

    return sorted(result)

def process_blocklists(blocklist_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    parsed_blocklists = {}
    all_bump_domains = set()

    if not os.path.exists(blocklist_dir):
        print(f"[process_blocklists] WARNING: Directory '{blocklist_dir}' does not exist.")
        return parsed_blocklists

    for filename in sorted(os.listdir(blocklist_dir)):
        if not filename.endswith(".txt"):
            continue

        filepath = os.path.join(blocklist_dir, filename)
        plain_domains = set()
        path_rules = []

        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if "/" in line:
                        # Entry contains URL path (e.g. steamcommunity.com/market)
                        parts = line.split("/", 1)
                        raw_domain = parts[0].strip()
                        path = "/" + parts[1].strip()

                        clean_domain = raw_domain.lstrip(".")
                        if not clean_domain:
                            continue

                        bump_domain = f".{clean_domain}"
                        all_bump_domains.add(bump_domain)
                        path_rules.append({
                            "raw_domain": raw_domain,
                            "clean_domain": clean_domain,
                            "bump_domain": bump_domain,
                            "path": path
                        })
                    else:
                        # Plain domain entry (e.g. .facebook.com or pornhub.com)
                        plain_domains.add(line)
        except Exception as e:
            print(f"[process_blocklists] Error processing {filepath}: {e}")

        # Deduplicate plain domains for this specific blocklist
        dedup_plain = deduplicate_domains(plain_domains)

        # Write per-blocklist clean domain ACL file
        domain_acl_filename = f"domains_{filename}.acl"
        domain_acl_file = os.path.join(output_dir, domain_acl_filename)
        with open(domain_acl_file, "w", encoding="utf-8") as f:
            f.write(f"# Auto-generated clean domain blocklist for {filename}\n")
            for dom in dedup_plain:
                f.write(f"{dom}\n")

        parsed_blocklists[filename] = {
            "domain_acl_file": domain_acl_file,
            "domain_acl_filename": domain_acl_filename,
            "plain_domains": dedup_plain,
            "path_rules": path_rules
        }

    # Write overall bump_domains.acl
    dedup_bump_domains = deduplicate_domains(all_bump_domains)
    bump_file = os.path.join(output_dir, "bump_domains.acl")
    with open(bump_file, "w", encoding="utf-8") as f:
        f.write("# Auto-generated: Domains requiring SSL Bumping for deep URL inspection\n")
        for domain in dedup_bump_domains:
            f.write(f"{domain}\n")
    print(f"[process_blocklists] Wrote {len(dedup_bump_domains)} bump domains across {len(parsed_blocklists)} blocklists to {bump_file}")

    # Write legacy domain_blocklists.acl and url_blocklists.acl as headers only (Web UI manages all blocking now)
    domain_file = os.path.join(output_dir, "domain_blocklists.acl")
    with open(domain_file, "w", encoding="utf-8") as f:
        f.write("# Auto-generated: Legacy plain domain blocklists file (All blocking is now managed by Web UI in rules.acl)\n")

    url_file = os.path.join(output_dir, "url_blocklists.acl")
    with open(url_file, "w", encoding="utf-8") as f:
        f.write("# Auto-generated: Legacy URL blocklists file (All blocking is now managed by Web UI in rules.acl)\n")

    return parsed_blocklists

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
