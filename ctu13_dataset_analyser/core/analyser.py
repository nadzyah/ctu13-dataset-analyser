"""
PcapAnalyser class for processing PCAP files and extracting session information.
"""

import logging
from collections import defaultdict
from typing import Dict, Set, Tuple

from scapy.utils import RawPcapReader

from ctu13_dataset_analyser.core.session import Session
from ctu13_dataset_analyser.utils.packet_parser import get_packet_info

# Type aliases
SessionKey = Tuple[
    str, str, int, int, str
]  # (src_ip, dst_ip, src_port, dst_port, proto)
BidirectionalSessionKey = Tuple[str, str, str]  # (ip1, ip2, proto)

logger = logging.getLogger(__name__)


class PcapAnalyser:
    """Class to analyze PCAP files and extract session information."""

    def __init__(self, botnet_ips: Set[str], normal_ips: Set[str]):
        self.botnet_ips = botnet_ips
        self.normal_ips = normal_ips
        self.sessions = defaultdict(dict)

    def process_pcap_file(
        self, pcap_file: str
    ) -> Dict[BidirectionalSessionKey, Session]:
        """Process a PCAP file and extract all sessions."""
        logger.info(f"Processing file: {pcap_file}")

        # Dictionary to store unidirectional sessions
        unidirectional_sessions: Dict[SessionKey, Session] = {}

        # Dictionary to map unidirectional session keys to bidirectional session keys
        session_key_mapping: Dict[SessionKey, BidirectionalSessionKey] = {}

        # Dictionary to store the final bidirectional sessions
        bidirectional_sessions: Dict[BidirectionalSessionKey, Session] = {}

        try:
            # First pass: identify all sessions
            for pkt_data, pkt_metadata in RawPcapReader(pcap_file):
                try:
                    # Parse packet using the utility function
                    pkt_info = get_packet_info(pkt_data)
                    if not pkt_info:
                        continue

                    src_ip = pkt_info["src_ip"]
                    dst_ip = pkt_info["dst_ip"]
                    src_port = pkt_info["src_port"]
                    dst_port = pkt_info["dst_port"]
                    proto = pkt_info["proto"]

                    # Create session keys
                    forward_key = (src_ip, dst_ip, src_port, dst_port, proto)
                    reverse_key = (dst_ip, src_ip, dst_port, src_port, proto)

                    # Sort IPs to create a consistent bidirectional key
                    ip_pair = tuple(sorted([src_ip, dst_ip]))
                    bidir_key = (ip_pair[0], ip_pair[1], proto)

                    # Create or update session
                    if (
                        forward_key not in unidirectional_sessions
                        and reverse_key not in unidirectional_sessions
                    ):
                        # New session
                        session = Session(src_ip, dst_ip, src_port, dst_port, proto)
                        unidirectional_sessions[forward_key] = session
                        session_key_mapping[forward_key] = bidir_key
                        bidirectional_sessions[bidir_key] = session

                    # Determine packet direction
                    if forward_key in unidirectional_sessions:
                        direction = "sent"
                        session_key = forward_key
                    else:
                        direction = "received"
                        session_key = reverse_key

                    # Map to bidirectional session
                    bidir_key = session_key_mapping.get(session_key, bidir_key)

                    # Add packet to session
                    session = bidirectional_sessions[bidir_key]
                    session.add_packet(pkt_data, pkt_metadata, direction)

                except Exception as e:
                    logger.warning(f"Error processing packet: {e}")
                    continue

            # Set labels for all sessions
            for session in bidirectional_sessions.values():
                session.set_label(self.botnet_ips, self.normal_ips)

            # Filter to only include bidirectional sessions
            bidirectional_sessions = {
                k: v
                for k, v in bidirectional_sessions.items()
                if v.has_bidirectional_traffic()
            }

            logger.info(
                f"Extracted {len(bidirectional_sessions)} bidirectional sessions from {pcap_file}"
            )
            return bidirectional_sessions

        except Exception as e:
            logger.error(f"Error processing PCAP file {pcap_file}: {e}")
            return {}
