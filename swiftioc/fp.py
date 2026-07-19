"""Bogon-IP and well-known-benign-host filtering."""
from __future__ import annotations

import ipaddress
from typing import Set, Tuple

from .models import _URL_HEAD_RE, _split_authority, refang


# ---------------- false-positive / bogon filtering ----------------
# Values that are never actionable threat indicators and only add noise to a
# feed. Bogon IP ranges (private, loopback, link-local, reserved, ...) are
# detected structurally via the ipaddress module.
FP_DOMAINS: Set[str] = {
    "example.com", "example.org", "example.net", "example.edu",
    "localhost", "localhost.localdomain", "test", "invalid", "local",
}
FP_DOMAIN_SUFFIXES: Tuple[str, ...] = (
    ".example.com", ".example.org", ".example.net",
    ".arpa", ".localhost", ".local", ".test", ".invalid",
)
FP_IPS: Set[str] = {"0.0.0.0", "255.255.255.255", "::", "::1"}


def _ip_is_bogon(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


def _net_is_bogon(cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return bool(
        net.is_private or net.is_loopback or net.is_link_local
        or net.is_multicast or net.is_reserved or net.is_unspecified
    )


def _domain_is_fp(host: str) -> bool:
    host = host.lower().rstrip(".")
    if host in FP_DOMAINS:
        return True
    return any(host.endswith(suffix) for suffix in FP_DOMAIN_SUFFIXES)


def is_false_positive(itype: str, value: str) -> bool:
    """Return True for well-known benign values that should not enter the feed."""
    raw = refang(value)
    if itype in {"ipv4", "ipv6"}:
        return raw in FP_IPS or _ip_is_bogon(raw)
    if itype in {"ipv4_cidr", "ipv6_cidr"}:
        return _net_is_bogon(raw)
    if itype == "domain":
        return _domain_is_fp(raw)
    if itype == "url":
        m = _URL_HEAD_RE.match(raw)
        if m:
            _userinfo_at, host, _port = _split_authority(m.group(3))
            return host in FP_IPS or _ip_is_bogon(host) or _domain_is_fp(host)
    return False

