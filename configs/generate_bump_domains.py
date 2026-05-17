#!/usr/bin/env python3
"""
Generate the selective-SSL-bump configuration from the raw blocklist files.

Two files are produced, and they must always be written together:

  bump_domains.acl   the domain list itself, derived from blocklist entries that
                     carry a URL path (e.g. 'steamcommunity.com/market')
  bump_domains.conf  the Squid directives that consume it. When no blocklist
                     defines a path rule this file contains no directives at all,
                     rather than declaring an ACL against an empty file — such an
                     ACL parses cleanly but can never match, so a broken
                     selective-bump setup would sail past 'squid -k parse'.

This runs at container start (docker-entrypoint.sh). The Web UI regenerates the
same two files on every policy compile, so blocklist edits made through the UI
take effect without waiting for a container restart.
"""
import os
import sys

def deduplicate_domains(domains):
    """
    Deduplicates domain strings for Squid dstdomain ACLs.
    Subsumption rules:
    - '.example.com' subsumes 'example.com' and all subdomains ('*.example.com').
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

def generate_bump_domains(blocklist_dir, output_file):
    bump_domains = set()
    if os.path.exists(blocklist_dir):
        for filename in sorted(os.listdir(blocklist_dir)):
            if not filename.endswith(".txt"):
                continue
            filepath = os.path.join(blocklist_dir, filename)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "/" in line:
                            parts = line.split("/", 1)
                            raw_domain = parts[0].strip().lstrip(".")
                            if raw_domain:
                                bump_domains.add(f".{raw_domain}")
            except Exception as e:
                print(f"[generate_bump_domains] Error parsing {filepath}: {e}")

    dedup = deduplicate_domains(bump_domains)
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("# Auto-generated: domains requiring SSL Bumping for deep URL path rules.\n")
        f.write("# Source: block-lists/*.txt entries of the form 'domain/path'.\n")
        for domain in dedup:
            f.write(f"{domain}\n")

    # Emit the matching directives file. squid.conf includes this, never the .acl
    # directly, so an empty domain list yields no ACL rather than a dead one.
    conf_file = os.path.join(os.path.dirname(os.path.abspath(output_file)), "bump_domains.conf")
    with open(conf_file, "w", encoding="utf-8") as f:
        f.write("# Auto-generated Squid directives for deep URL path SSL bumping.\n")
        if dedup:
            f.write(f'acl bump_domains dstdomain "{os.path.abspath(output_file)}"\n')
            f.write("ssl_bump bump bump_domains\n")
        else:
            f.write("# No blocklist defines a 'domain/path' rule, so no global bump\n")
            f.write("# ACL is emitted. Declaring one against an empty file would\n")
            f.write("# parse cleanly but never match.\n")

    print(f"[generate_bump_domains] Wrote {len(dedup)} bump domain(s) to {output_file}")
    print(f"[generate_bump_domains] Wrote directives to {conf_file}")

if __name__ == "__main__":
    bl_dir = sys.argv[1] if len(sys.argv) > 1 else "/etc/squid/block-lists"
    out_file = sys.argv[2] if len(sys.argv) > 2 else "/etc/squid/configs/bump_domains.acl"
    if not os.path.exists(bl_dir):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        local_bl = os.path.abspath(os.path.join(script_dir, "..", "block-lists"))
        local_out = os.path.abspath(os.path.join(script_dir, "bump_domains.acl"))
        if os.path.exists(local_bl):
            bl_dir = local_bl
            out_file = local_out
    generate_bump_domains(bl_dir, out_file)
