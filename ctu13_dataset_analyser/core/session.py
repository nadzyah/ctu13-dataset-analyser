"""
Memory-optimized Session class for tracking and analyzing network traffic sessions.
Fixed classification logic to match CTU-13 dataset distributions.
"""

import numpy as np
import time
from typing import Dict, List, Set, Any, Optional


class Session:
    """Class to store and analyze session information."""

    def __init__(
        self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str
    ):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto

        # Instead of storing entire packets, store only essential information
        self.sent_packet_info: List[Dict[str, Any]] = []
        self.received_packet_info: List[Dict[str, Any]] = []

        # Session timing info
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

        # Traffic labels
        self.is_botnet = False
        self.is_normal = False
        self.is_cc = False
        self.is_background = False
        self.session_label = "unknown"

    def add_packet(self, pkt_data: bytes, pkt_metadata: Any, direction: str) -> None:
        """
        Add a packet to the session with the specified direction.
        """
        # Extract timestamp from metadata
        timestamp = self._extract_timestamp(pkt_metadata)

        # Extract packet size
        size = self._extract_packet_size(pkt_data, pkt_metadata)

        # Update session timing information
        if self.start_time is None or timestamp < self.start_time:
            self.start_time = timestamp

        if self.end_time is None or timestamp > self.end_time:
            self.end_time = timestamp

        # Create minimal packet info
        packet_info = {"timestamp": timestamp, "size": size}

        # Add packet info to the appropriate list based on direction
        if direction == "sent":
            self.sent_packet_info.append(packet_info)
        else:
            self.received_packet_info.append(packet_info)

    def _extract_timestamp(self, pkt_metadata: Any) -> float:
        """
        Extract timestamp from packet metadata with flexible format handling.

        Handles different timestamp formats:
        1. Scapy RawPcapReader format (sec, usec)
        2. High/low format (tshigh, tslow)
        3. sec attribute
        4. time attribute

        Returns:
            float: Timestamp in seconds (Unix time)
        """
        try:
            # Try different timestamp formats

            # Format 1: sec, usec attributes (common in newer Scapy versions)
            if hasattr(pkt_metadata, "sec") and hasattr(pkt_metadata, "usec"):
                return float(pkt_metadata.sec) + (float(pkt_metadata.usec) / 1000000.0)

            # Format 2: High/low format (used in some pcap formats)
            elif hasattr(pkt_metadata, "tshigh") and hasattr(pkt_metadata, "tslow"):
                return float((pkt_metadata.tshigh << 32) | pkt_metadata.tslow)

            # Format 3: time attribute
            elif hasattr(pkt_metadata, "time"):
                return float(pkt_metadata.time)

            # Format 4: timestamp attribute
            elif hasattr(pkt_metadata, "timestamp"):
                return float(pkt_metadata.timestamp)

            # Format 5: ts attribute (used in some pcap formats)
            elif hasattr(pkt_metadata, "ts"):
                if isinstance(pkt_metadata.ts, tuple) and len(pkt_metadata.ts) == 2:
                    # Tuple format (seconds, microseconds)
                    return float(pkt_metadata.ts[0]) + (
                        float(pkt_metadata.ts[1]) / 1000000.0
                    )
                else:
                    return float(pkt_metadata.ts)

            # Fallback: Use current time if no timestamp can be extracted
            else:
                return time.time()

        except (AttributeError, TypeError):
            # Return current time if there's an error
            return time.time()

    def _extract_packet_size(self, pkt_data: bytes, pkt_metadata: Any) -> int:
        """
        Extract packet size from packet data or metadata with flexible format handling.

        Returns:
            int: Packet size in bytes
        """
        try:
            # Try different size formats

            # Format 1: wirelen attribute
            if hasattr(pkt_metadata, "wirelen"):
                return pkt_metadata.wirelen

            # Format 2: len attribute
            elif hasattr(pkt_metadata, "len"):
                return pkt_metadata.len

            # Format 3: caplen attribute
            elif hasattr(pkt_metadata, "caplen"):
                return pkt_metadata.caplen

            # Fallback: Use the length of the packet data
            else:
                return len(pkt_data)

        except (AttributeError, TypeError):
            # Return the length of the packet data if there's an error
            return len(pkt_data)

    def has_bidirectional_traffic(self) -> bool:
        """Check if the session has at least one packet in each direction."""
        return len(self.sent_packet_info) > 0 and len(self.received_packet_info) > 0

    def set_label(self, botnet_ips: Set[str], normal_ips: Set[str]) -> None:
        """
        Set the label for this session based on the known IPs.

        This implementation follows the CTU-13 dataset labeling conventions:
        1. Command and Control: Communication between botnet and specific C&C servers
           (very specific and rare pattern)
        2. Botnet: Traffic involving infected machines
        3. Normal: Legitimate traffic involving known normal IPs
        4. Background: All other traffic (majority of traffic)

        Args:
            botnet_ips: Set of known botnet IP addresses
            normal_ips: Set of known normal/legitimate IP addresses
        """
        src_is_botnet = self.src_ip in botnet_ips
        dst_is_botnet = self.dst_ip in botnet_ips

        src_is_normal = self.src_ip in normal_ips
        dst_is_normal = self.dst_ip in normal_ips

        # The logic follows the CTU-13 dataset conventions more closely

        # C&C traffic is very specific and rare
        # Usually involves communication with external C&C servers on specific ports
        is_cc_connection = False
        common_cc_ports = {80, 443, 8080, 1080, 53}  # Common C&C ports

        # Check for C&C connection patterns
        if (src_is_botnet and not dst_is_botnet and not dst_is_normal) or (
            dst_is_botnet and not src_is_botnet and not src_is_normal
        ):
            # Communication with an unknown external entity
            # Check if it's using a common C&C port
            if self.dst_port in common_cc_ports or self.src_port in common_cc_ports:
                # DNS (port 53) traffic is almost never C&C in this dataset
                if (self.dst_port == 53 or self.src_port == 53) and (
                    self.proto == "UDP"
                ):
                    is_cc_connection = False
                else:
                    is_cc_connection = True

                    # Special case: TCP port 25 (SMTP) is usually for spam, not C&C
                    if (
                        self.dst_port == 25 or self.src_port == 25
                    ) and self.proto == "TCP":
                        is_cc_connection = False

        # Classify based on the patterns in the CTU-13 dataset
        if is_cc_connection:
            # Command and Control traffic
            self.is_cc = True
            self.session_label = "command-and-control"
        elif src_is_botnet or dst_is_botnet:
            # Botnet traffic (including botnet-to-botnet)
            self.is_botnet = True
            if src_is_botnet and dst_is_botnet:
                self.session_label = "botnet-to-botnet"
            else:
                self.session_label = "botnet"
        elif src_is_normal or dst_is_normal:
            # Normal/legitimate traffic
            self.is_normal = True
            self.session_label = "normal"
        else:
            # Background traffic (majority of traffic)
            self.is_background = True
            self.session_label = "background"

    def calculate_metrics(self) -> Dict[str, Any]:
        """Calculate all session metrics."""
        if not self.has_bidirectional_traffic():
            return {}

        metrics = {}

        # Basic packet counts
        metrics["spc"] = len(self.sent_packet_info)
        metrics["rpc"] = len(self.received_packet_info)

        # Packet size metrics
        sent_sizes = [pkt["size"] for pkt in self.sent_packet_info]
        received_sizes = [pkt["size"] for pkt in self.received_packet_info]

        metrics["tss"] = sum(sent_sizes)
        metrics["tsr"] = sum(received_sizes)
        metrics["smin"] = min(sent_sizes) if sent_sizes else 0
        metrics["smax"] = max(sent_sizes) if sent_sizes else 0
        metrics["rmin"] = min(received_sizes) if received_sizes else 0
        metrics["rmax"] = max(received_sizes) if received_sizes else 0
        metrics["savg"] = np.mean(sent_sizes) if sent_sizes else 0
        metrics["ravg"] = np.mean(received_sizes) if received_sizes else 0
        metrics["svar"] = (
            np.mean(np.abs(np.array(sent_sizes) - metrics["savg"])) if sent_sizes else 0
        )
        metrics["rvar"] = (
            np.mean(np.abs(np.array(received_sizes) - metrics["ravg"]))
            if received_sizes
            else 0
        )

        # Calculate time intervals between packets
        s_diff_times = self._calculate_time_diffs(self.sent_packet_info)
        r_diff_times = self._calculate_time_diffs(self.received_packet_info)

        # Time interval metrics for sent packets
        if s_diff_times:
            metrics["sintmin"] = min(s_diff_times)
            metrics["sintmax"] = max(s_diff_times)
            metrics["sintavg"] = np.mean(s_diff_times)
            metrics["sintvar"] = np.mean(
                np.abs(np.array(s_diff_times) - metrics["sintavg"])
            )
        else:
            metrics["sintmin"] = 0
            metrics["sintmax"] = 0
            metrics["sintavg"] = 0
            metrics["sintvar"] = 0

        # Time interval metrics for received packets
        if r_diff_times:
            metrics["rintmin"] = min(r_diff_times)
            metrics["rintmax"] = max(r_diff_times)
            metrics["rintavg"] = np.mean(r_diff_times)
            metrics["rintvar"] = np.mean(
                np.abs(np.array(r_diff_times) - metrics["rintavg"])
            )
        else:
            metrics["rintmin"] = 0
            metrics["rintmax"] = 0
            metrics["rintavg"] = 0
            metrics["rintvar"] = 0

        # Total session time
        metrics["time"] = (
            self.end_time - self.start_time
            if (self.end_time and self.start_time)
            else 0
        )

        # Add session label information
        metrics["session_label"] = self.session_label
        metrics["is_botnet"] = int(self.is_botnet)
        metrics["is_normal"] = int(self.is_normal)
        metrics["is_cc"] = int(self.is_cc)
        metrics["is_background"] = int(self.is_background)

        # Add session identification fields
        metrics["src_ip"] = self.src_ip
        metrics["dst_ip"] = self.dst_ip
        metrics["src_port"] = self.src_port
        metrics["dst_port"] = self.dst_port
        metrics["proto"] = self.proto

        return metrics

    def _calculate_time_diffs(self, packet_info: List[Dict[str, Any]]) -> List[float]:
        """Calculate time differences between consecutive packets."""
        if len(packet_info) < 2:
            return []

        # Sort by timestamp to ensure correct ordering
        sorted_packets = sorted(packet_info, key=lambda x: x["timestamp"])

        # Calculate differences
        diff_times = []
        for i in range(len(sorted_packets) - 1):
            start_time = sorted_packets[i]["timestamp"]
            end_time = sorted_packets[i + 1]["timestamp"]
            diff_times.append(end_time - start_time)

        return diff_times
