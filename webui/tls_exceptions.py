"""Validated shared TLS compatibility exceptions; no runtime DNS expansion."""
import ipaddress
import re

# Vivox provider ranges, published 2026-08-06. Recheck when service endpoints change.
# https://support.unity.com/hc/en-us/articles/4407491745940
DEFAULT_EXCEPTIONS = [{"domain": "vivox.com", "destination_networks": [
    "85.236.96.0/21", "85.236.104.0/23"], "enabled": True}]


def validate_exceptions(entries):
    if not isinstance(entries, list) or len(entries) > 100:
        raise ValueError("Expected at most 100 TLS exceptions")
    result, seen = [], set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"domain", "destination_networks", "enabled"}:
            raise ValueError("Each exception requires domain, destination_networks and enabled")
        domain = entry["domain"]
        if not isinstance(domain, str):
            raise ValueError("Domain must be text")
        domain = domain.lower().strip().rstrip(".")
        if len(domain) > 253 or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", domain):
            raise ValueError("Enter a DNS domain without a wildcard, scheme or path")
        if domain in seen:
            raise ValueError("Duplicate domain: " + domain)
        seen.add(domain)
        if type(entry["enabled"]) is not bool:
            raise ValueError("Enabled must be true or false")
        networks = entry["destination_networks"]
        if not isinstance(networks, list) or len(networks) > 100:
            raise ValueError("Expected at most 100 destination networks per service")
        normalized = []
        for network in networks:
            if not isinstance(network, str):
                raise ValueError("Networks must be CIDR strings")
            net = ipaddress.ip_network(network.strip(), strict=True)
            if (not net.network_address.is_global or not net.broadcast_address.is_global
                    or net.is_multicast or net.is_reserved):
                raise ValueError("Use public destination networks only")
            normalized.append(str(net))
        result.append(dict(domain=domain, destination_networks=sorted(set(normalized)), enabled=entry["enabled"]))
    return result


def render_exceptions(entries):
    lines = ["# Generated TLS exceptions: all devices, all times.",
             "acl tls_exception_step1 at_step SslBump1",
             "acl tls_exception_https port 443",
             "acl tls_exception_explicit myportname explicit_proxy"]
    for i, entry in enumerate(validate_exceptions(entries)):
        if not entry["enabled"]:
            continue
        name = "tls_exception_" + str(i)
        lines += [f"acl {name}_domain dstdomain -n .{entry['domain']}",
                  f"ssl_bump splice tls_exception_step1 tls_exception_https tls_exception_explicit {name}_domain"]
        if entry["destination_networks"]:
            lines += [f"acl {name}_net dst " + " ".join(entry["destination_networks"]),
                      f"ssl_bump splice tls_exception_step1 tls_exception_https {name}_net"]
    return "\n".join(lines) + "\n"
