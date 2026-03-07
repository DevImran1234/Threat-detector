# agent/network_capture.py
"""
Live packet capture utilities using PyShark (tshark backend).
Requires Wireshark/tshark installed and available on PATH.

Windows tip:
  - Install Wireshark (includes tshark) + Npcap.
  - Run terminal as Administrator for live capture if needed.
"""

from __future__ import annotations
import shutil
import datetime
from typing import Dict, Iterable, Optional

try:
    import pyshark 
except Exception as e:
    raise RuntimeError("PyShark not installed. Run: pip install pyshark") from e


def ensure_tshark_available() -> None:
    """Raise if tshark is not found on PATH."""
    if not shutil.which("tshark"):
        raise RuntimeError(
            "tshark not found. Install Wireshark and ensure 'tshark' is on PATH.\n"
            "Download: https://www.wireshark.org/download.html"
        )


def packet_to_event(pkt) -> Dict:
    """
    Convert a PyShark packet to a normalized 'event' dict your engine understands.
    We pull the most common fields defensively (IP, ports, protocol, DNS/HTTP info).
    """
    # Basics
    ts = getattr(pkt, "sniff_time", datetime.datetime.utcnow())
    event = {
        "event_id": getattr(pkt, "number", None),
        "event_type": "network_traffic",         # policy can include this type
        "severity": 0.0,                         # default; engine may enrich/compute
        "timestamp": ts.replace(microsecond=0).isoformat() + "Z",
        "username": None,                        # not applicable for packets
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "country": None,                         # optional, left None
        "indicators": [],
        "description": "Live network packet captured via PyShark/tshark",
        "protocol": None,
    }

    # IP layer
    if hasattr(pkt, "ip"):
        event["src_ip"] = getattr(pkt.ip, "src", None)
        event["dst_ip"] = getattr(pkt.ip, "dst", None)
        event["protocol"] = getattr(pkt.ip, "proto", None)

    # Transport ports
    if hasattr(pkt, "tcp"):
        event["src_port"] = getattr(pkt.tcp, "srcport", None)
        event["dst_port"] = getattr(pkt.tcp, "dstport", None)
        event["protocol"] = "TCP"
    elif hasattr(pkt, "udp"):
        event["src_port"] = getattr(pkt.udp, "srcport", None)
        event["dst_port"] = getattr(pkt.udp, "dstport", None)
        event["protocol"] = "UDP"

    # DNS
    if hasattr(pkt, "dns"):
        qname = getattr(pkt.dns, "qry_name", None)
        if qname:
            event["indicators"].append(f"DNS:{qname}")

    # HTTP
    if hasattr(pkt, "http"):
        host = getattr(pkt.http, "host", None)
        uri  = getattr(pkt.http, "request_full_uri", None) or getattr(pkt.http, "request_uri", None)
        if host:
            event["indicators"].append(f"HTTP_HOST:{host}")
        if uri:
            event["indicators"].append(f"HTTP_URI:{uri}")

    # TLS SNI
    if hasattr(pkt, "tls"):
        sni = getattr(pkt.tls, "handshake_extensions_server_name", None)
        if sni:
            event["indicators"].append(f"SNI:{sni}")

    # Very light heuristic to seed a severity (you can tune this or let engine handle)
    score = 0.1
    if any(k in (event.get("protocol") or "").upper() for k in ["TCP", "UDP"]):
        score += 0.05
    if any(ind.startswith(("DNS:", "HTTP_", "SNI:")) for ind in event["indicators"]):
        score += 0.2
    event["severity"] = min(1.0, round(score, 2))

    return event


def sniff_live(
    interface: str,
    packet_count: int = 50,
    bpf_filter: Optional[str] = None,
    display_filter: Optional[str] = None,
    decode_as: Optional[Iterable[str]] = None,
) -> Iterable[Dict]:
    """
    Capture packets live and yield normalized event dicts.
    - interface: e.g., "Ethernet", "Wi-Fi" (Windows) or "eth0", "wlan0" (Linux)
    - packet_count: stop after N packets
    - bpf_filter: e.g., 'tcp port 80' (capture filter)
    - display_filter: e.g., 'http or dns' (tshark display filter)
    - decode_as: iterable of decode-as strings, e.g. ["tcp.port==443,http"]

    Yields dicts one by one to stream into the decision engine.
    """
    ensure_tshark_available()

    kwargs = {}
    if bpf_filter:
        kwargs["bpf_filter"] = bpf_filter
    if display_filter:
        kwargs["display_filter"] = display_filter
    if decode_as:
        kwargs["decode_as"] = list(decode_as)

    cap = pyshark.LiveCapture(interface=interface, **kwargs)
    for pkt in cap.sniff_continuously(packet_count=packet_count):
        try:
            yield packet_to_event(pkt)
        except Exception:
            # Skip packets we failed to parse robustly
            continue
