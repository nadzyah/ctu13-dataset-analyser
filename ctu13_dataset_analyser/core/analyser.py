"""
PcapAnalyser class for processing PCAP files and extracting session information.
"""

import logging
import gc
from typing import Dict, Set, Tuple, List, Any, Optional, Generator

from scapy.utils import PcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP

from ctu13_dataset_analyser.core.session import Session

# Type aliases
SessionKey = Tuple[
    str, str, int, int, str
]  # (src_ip, dst_ip, src_port, dst_port, proto)
BidirectionalSessionKey = Tuple[str, str, str]  # (ip1, ip2, proto)

logger = logging.getLogger(__name__)


class PcapAnalyser:
    """Class to analyze PCAP files and extract session information."""

    def __init__(
        self,
        botnet_ips: Set[str],
        normal_ips: Set[str],
        proto_filter: Optional[str] = None,
    ):
        """
        Initialize the PCAP analyzer.

        Args:
            botnet_ips: Set of known botnet IP addresses
            normal_ips: Set of known normal IP addresses
            proto_filter: Optional protocol filter (TCP, UDP, ICMP)
        """
        self.botnet_ips = botnet_ips
        self.normal_ips = normal_ips
        self.proto_filter = proto_filter
        self.BATCH_SIZE = 50000  # Process this many packets at a time

    def process_pcap_file(
        self, pcap_file: str
    ) -> Dict[BidirectionalSessionKey, Session]:
        """
        Process a PCAP file in batches and extract all sessions.

        Args:
            pcap_file: Path to the PCAP file

        Returns:
            Dictionary of bidirectional sessions
        """
        logger.info(f"Processing file: {pcap_file}")

        # Dictionary to store the final bidirectional sessions
        bidirectional_sessions: Dict[BidirectionalSessionKey, Session] = {}

        # Dictionary to map unidirectional session keys to bidirectional session keys
        session_key_mapping: Dict[SessionKey, BidirectionalSessionKey] = {}

        try:
            packet_count = 0
            batch_count = 0

            # Process the PCAP file in batches
            with PcapReader(pcap_file) as pcap_reader:
                current_batch = []

                for pkt_data in pcap_reader:
                    current_batch.append(pkt_data)
                    packet_count += 1

                    # When we reach batch size, process the batch
                    if len(current_batch) >= self.BATCH_SIZE:
                        self._process_packet_batch(
                            current_batch, bidirectional_sessions, session_key_mapping
                        )
                        batch_count += 1
                        logger.debug(
                            f"Processed batch {batch_count} ({packet_count} packets so far)"
                        )
                        current_batch = []  # Clear batch for memory efficiency
                        gc.collect()  # Explicitly trigger garbage collection

                # Process any remaining packets
                if current_batch:
                    self._process_packet_batch(
                        current_batch, bidirectional_sessions, session_key_mapping
                    )
                    batch_count += 1

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
                f"Extracted {len(bidirectional_sessions)} bidirectional sessions from {pcap_file} ({packet_count} packets processed)"
            )
            return bidirectional_sessions

        except Exception as e:
            logger.error(f"Error processing PCAP file {pcap_file}: {e}")
            return {}

    def process_pcap_file_generator(
        self, pcap_file: str
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Process a PCAP file and yield session metrics incrementally.

        Args:
            pcap_file: Path to the PCAP file

        Yields:
            Dictionary of session metrics for each bidirectional session
        """
        logger.info(f"Processing file with generator: {pcap_file}")

        try:
            # Get all sessions
            sessions = self.process_pcap_file(pcap_file)

            # Yield metrics for each session
            for session in sessions.values():
                if session.has_bidirectional_traffic():
                    metrics = session.calculate_metrics()
                    if metrics:
                        yield metrics

            # Explicitly clear sessions and trigger garbage collection
            sessions.clear()
            gc.collect()

        except Exception as e:
            logger.error(f"Error in generator for PCAP file {pcap_file}: {e}")

    def _process_packet_batch(
        self,
        batch: List[Any],
        bidirectional_sessions: Dict[BidirectionalSessionKey, Session],
        session_key_mapping: Dict[SessionKey, BidirectionalSessionKey],
    ) -> None:
        """
        Process a batch of packets and update sessions.

        Args:
            batch: List of packets to process
            bidirectional_sessions: Dictionary of sessions to update
            session_key_mapping: Mapping from unidirectional to bidirectional keys
        """
        for pkt in batch:
            try:
                # Parse Ethernet frame if this is raw packet data
                if isinstance(pkt, bytes):
                    pkt = Ether(pkt)

                # Skip non-Ethernet frames or frames without type
                if not isinstance(pkt, Ether) or "type" not in pkt.fields:
                    continue

                # Check if packet contains IP
                if IP not in pkt:
                    continue

                ip_pkt = pkt[IP]
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
                elif UDP in ip_pkt:
                    proto = "UDP"
                    layer4_pkt = ip_pkt[UDP]
                    src_port = layer4_pkt.sport
                    dst_port = layer4_pkt.dport
                elif ICMP in ip_pkt:
                    proto = "ICMP"
                    icmp_pkt = ip_pkt[ICMP]
                    src_port = icmp_pkt.type if hasattr(icmp_pkt, "type") else 0
                    dst_port = icmp_pkt.code if hasattr(icmp_pkt, "code") else 0
                else:
                    # Skip other protocols
                    continue

                # Early protocol filtering to save memory
                if self.proto_filter and proto != self.proto_filter:
                    continue

                # Create session keys
                forward_key = (src_ip, dst_ip, src_port, dst_port, proto)
                reverse_key = (dst_ip, src_ip, dst_port, src_port, proto)

                # Sort IPs to create a consistent bidirectional key
                ip_pair = tuple(sorted([src_ip, dst_ip]))
                bidir_key = (ip_pair[0], ip_pair[1], proto)

                # Get packet metadata
                pkt_metadata = pkt.time if hasattr(pkt, "time") else None
                if pkt_metadata is None and hasattr(pkt, "wirelen"):
                    # Create simple metadata object
                    class SimpleMetadata:
                        pass

                    pkt_metadata = SimpleMetadata()
                    pkt_metadata.time = 0
                    pkt_metadata.wirelen = len(pkt)

                # Determine direction and session
                if forward_key in session_key_mapping:
                    direction = "sent"
                    session_key = session_key_mapping[forward_key]
                elif reverse_key in session_key_mapping:
                    direction = "received"
                    session_key = session_key_mapping[reverse_key]
                else:
                    # New session
                    direction = "sent"
                    session = Session(src_ip, dst_ip, src_port, dst_port, proto)
                    session_key_mapping[forward_key] = bidir_key
                    bidirectional_sessions[bidir_key] = session
                    session_key = bidir_key

                # Add packet to session
                if session_key in bidirectional_sessions:
                    # Get raw bytes for memory efficiency
                    raw_pkt = bytes(pkt) if not isinstance(pkt, bytes) else pkt
                    bidirectional_sessions[session_key].add_packet(
                        raw_pkt, pkt_metadata, direction
                    )

            except Exception as e:
                logger.debug(f"Error processing packet: {e}")
                continue
