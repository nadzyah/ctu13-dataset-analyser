#!/usr/bin/env python3
"""
Main entry point for the CTU-13 PCAP Analyser.
Memory-optimized version that writes results incrementally.
"""

import os
import sys
import logging
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Dict, Any, Set, Optional

from ctu13_dataset_analyser.core.analyser import PcapAnalyser
from ctu13_dataset_analyser.utils.ip_extractor import extract_known_ips
from ctu13_dataset_analyser.utils.csv_writer import (
    initialize_csv_file,
    append_results_to_csv,
    get_prioritized_fieldnames,
)
from ctu13_dataset_analyser.cli_arguments import parse_arguments

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("ctu13_dataset_analyser")

# Global variables for shared state
OUTPUT_FILE = None
FIELDNAMES = None
BOTNET_IPS = set()
NORMAL_IPS = set()


def process_pcap_file(
    pcap_file: str, scenario: str, botnet_ips: Set[str], normal_ips: Set[str]
) -> List[Dict[str, Any]]:
    """Process a single PCAP file and return session metrics."""
    logger.info(f"Processing PCAP file: {pcap_file} from scenario {scenario}")

    results = []
    analyser = PcapAnalyser(botnet_ips, normal_ips)

    try:
        # Process the PCAP file
        sessions = analyser.process_pcap_file(pcap_file)

        # Calculate metrics for each session
        for session in sessions.values():
            metrics = session.calculate_metrics()
            if metrics:  # Skip empty metrics (non-bidirectional sessions)
                # Add scenario information
                metrics["scenario"] = scenario
                metrics["pcap_file"] = os.path.basename(pcap_file)
                results.append(metrics)

        logger.info(f"Extracted {len(results)} sessions from {pcap_file}")
        return results

    except Exception as e:
        logger.error(f"Error processing PCAP file {pcap_file}: {e}")
        return []


def process_scenario(
    scenario_dir: str,
    output_file: str,
    fieldnames: List[str],
    botnet_ips: Set[str],
    normal_ips: Set[str],
    filter_proto: Optional[str] = None,
) -> None:
    """
    Process a single CTU-13 scenario directory and write results directly to CSV.

    Args:
        scenario_dir: Path to the scenario directory
        output_file: Path to the output CSV file
        fieldnames: CSV field names
        botnet_ips: Set of known botnet IP addresses
        normal_ips: Set of known normal IP addresses
        filter_proto: Optional protocol filter (TCP, UDP, ICMP)
    """
    logger.info(f"Processing scenario directory: {scenario_dir}")
    scenario = os.path.basename(scenario_dir)

    # Find all PCAP files in the directory
    pcap_files = []
    for file in os.listdir(scenario_dir):
        if file.endswith(".pcap"):
            pcap_files.append(os.path.join(scenario_dir, file))

    if not pcap_files:
        logger.warning(f"No PCAP files found in {scenario_dir}")
        return

    # Process each PCAP file
    all_session_results = []
    for pcap_file in pcap_files:
        # Process the file and get session metrics
        session_results = process_pcap_file(pcap_file, scenario, botnet_ips, normal_ips)

        # Apply protocol filter if specified
        if filter_proto and filter_proto != "ALL":
            session_results = [
                result
                for result in session_results
                if result.get("proto") == filter_proto
            ]

        # Write batch of results to CSV
        if session_results:
            append_results_to_csv(session_results, output_file, fieldnames)

        # Keep a small sample for logging
        all_session_results.extend(session_results[:5])  # Just keep up to 5 for logging

    logger.info(
        f"Completed scenario {scenario}: Processed {len(pcap_files)} PCAP files"
    )
    return


def process_scenario_wrapper(args):
    """Wrapper for process_scenario to unpack arguments for ProcessPoolExecutor."""
    scenario_dir, output_file, fieldnames, botnet_ips, normal_ips, filter_proto = args
    return process_scenario(
        scenario_dir, output_file, fieldnames, botnet_ips, normal_ips, filter_proto
    )


def run() -> None:
    """Main function to run the PCAP analyser."""
    start_time = time.time()

    # Parse command line arguments
    args = parse_arguments()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate dataset root directory
    if not os.path.isdir(args.dataset_root):
        logger.error(f"Dataset root directory not found: {args.dataset_root}")
        sys.exit(1)

    # Extract known IPs
    logger.info("Extracting known IPs from README files...")
    botnet_ips, normal_ips = extract_known_ips(args.dataset_root)
    logger.info(f"Found {len(botnet_ips)} botnet IPs and {len(normal_ips)} normal IPs")

    # Determine which scenarios to process
    scenarios = []
    if args.scenarios:
        for scenario in args.scenarios:
            scenario_dir = os.path.join(args.dataset_root, scenario)
            if os.path.isdir(scenario_dir):
                scenarios.append(scenario_dir)
            else:
                logger.warning(f"Scenario directory not found: {scenario_dir}")
    else:
        # Process all scenario directories
        for scenario in os.listdir(args.dataset_root):
            scenario_dir = os.path.join(args.dataset_root, scenario)
            if os.path.isdir(scenario_dir) and scenario.isdigit():
                scenarios.append(scenario_dir)

    if not scenarios:
        logger.error("No valid scenario directories found")
        sys.exit(1)

    logger.info(f"Will process {len(scenarios)} scenario directories")

    # Create a small sample of data to determine CSV fields
    logger.info("Creating initial data sample to determine CSV structure...")
    sample_scenario = scenarios[0]
    sample_pcap = None
    for file in os.listdir(sample_scenario):
        if file.endswith(".pcap"):
            sample_pcap = os.path.join(sample_scenario, file)
            break

    if not sample_pcap:
        logger.error(f"No PCAP file found in {sample_scenario} for field determination")
        sys.exit(1)

    # Get a small sample of data to determine fields
    sample_results = process_pcap_file(
        sample_pcap, os.path.basename(sample_scenario), botnet_ips, normal_ips
    )

    # Apply protocol filter to sample if needed
    if args.filter_proto != "ALL":
        sample_results = [
            r for r in sample_results if r.get("proto") == args.filter_proto
        ]

    if not sample_results:
        logger.error("Could not determine CSV fields from sample data")
        sys.exit(1)

    # Determine field names from sample
    fieldnames = get_prioritized_fieldnames(sample_results)

    # Initialize the CSV file with headers
    logger.info(f"Initializing output CSV file: {args.output}")
    initialize_csv_file(args.output, fieldnames)

    # Process scenarios
    if args.max_workers > 1 and len(scenarios) > 1:
        logger.info(f"Processing scenarios with {args.max_workers} workers in parallel")

        # Create argument tuples for each scenario
        scenario_args = [
            (
                scenario,
                args.output,
                fieldnames,
                botnet_ips,
                normal_ips,
                args.filter_proto,
            )
            for scenario in scenarios
        ]

        # Process scenarios in parallel
        with ProcessPoolExecutor(max_workers=args.max_workers) as executor:
            futures = [
                executor.submit(process_scenario_wrapper, arg) for arg in scenario_args
            ]

            # Track completion
            completed = 0
            for future in as_completed(futures):
                completed += 1
                try:
                    future.result()  # Check for exceptions
                    logger.info(
                        f"Progress: {completed}/{len(scenarios)} scenarios processed"
                    )
                except Exception as e:
                    logger.error(f"Error in worker process: {e}")
    else:
        # Process scenarios sequentially
        logger.info("Processing scenarios sequentially")
        for i, scenario in enumerate(scenarios, 1):
            try:
                process_scenario(
                    scenario,
                    args.output,
                    fieldnames,
                    botnet_ips,
                    normal_ips,
                    args.filter_proto,
                )
                logger.info(f"Progress: {i}/{len(scenarios)} scenarios processed")
            except Exception as e:
                logger.error(f"Error processing scenario {scenario}: {e}")

    # Report completion
    elapsed_time = time.time() - start_time
    logger.info(f"Analysis complete. Results written to {args.output}")
    logger.info(f"Total processing time: {elapsed_time:.2f} seconds")


if __name__ == "__main__":
    run()
