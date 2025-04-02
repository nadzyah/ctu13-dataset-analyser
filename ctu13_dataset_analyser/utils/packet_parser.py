"""
Utility functions for parsing packets from PCAP files.
"""

from typing import Dict, Optional, Any

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP


def get_packet_info(pkt_data: bytes) -> Optional[Dict[str, Any]]:
    """
    Extract relevant information from a packet.

    Args:
        pkt_data: Raw packet data

    Returns:
        Dictionary with packet information or None if packet should be skipped
    """
    try:
        # Parse Ethernet frame
        ether_pkt = Ether(pkt_data)
        if "type" not in ether_pkt.fields:
            return None  # Skip LLC frames

        # Check if packet contains IP
        if IP not in ether_pkt:
            return None

        ip_pkt = ether_pkt[IP]
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        # Determine protocol and ports
        proto = None
        src_port = 0
        dst_port = 0

        if TCP in ip_pkt:
            proto = "TCP"
            layer4_pkt = ip_pkt[TCP]
            src_port = layer4_pkt.sport
            dst_port = layer4_pkt.dport
            has_payload = len(layer4_pkt.payload) > 0
        elif UDP in ip_pkt:
            proto = "UDP"
            layer4_pkt = ip_pkt[UDP]
            src_port = layer4_pkt.sport
            dst_port = layer4_pkt.dport
            has_payload = len(layer4_pkt.payload) > 0
        elif ICMP in ip_pkt:
            proto = "ICMP"
            # For ICMP, use type and code as "ports"
            icmp_pkt = ip_pkt[ICMP]
            src_port = icmp_pkt.type
            dst_port = icmp_pkt.code
            has_payload = len(icmp_pkt.payload) > 0
        else:
            # Skip other protocols
            return None

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": proto,
            "has_payload": has_payload,
        }

    except Exception:
        return None
