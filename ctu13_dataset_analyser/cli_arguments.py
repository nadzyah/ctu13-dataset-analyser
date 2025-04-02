"""
Command-line argument parsing for CTU-13 PCAP Analyser.
"""

import argparse


def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="Analyze PCAP files from CTU-13 dataset",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("dataset_root", help="Root directory of the CTU-13 dataset")

    parser.add_argument(
        "--output", "-o", default="session_metrics.csv", help="Output CSV file"
    )

    parser.add_argument(
        "--scenarios",
        "-s",
        nargs="+",
        type=str,
        help="Specific scenario directories to process (e.g., 1 3 4)",
    )

    parser.add_argument(
        "--max-workers",
        "-w",
        type=int,
        default=4,
        help="Maximum number of worker processes",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    parser.add_argument(
        "--filter-proto",
        choices=["TCP", "UDP", "ICMP", "ALL"],
        default="ALL",
        help="Filter by protocol",
    )

    parser.add_argument(
        "--filter-label",
        choices=["botnet", "normal", "cc", "background", "ALL"],
        default="ALL",
        help="Filter by traffic label",
    )

    return parser.parse_args()
