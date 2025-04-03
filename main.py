#!/usr/bin/env python3
"""
Main entry point for the CTU-13 PCAP Analyser.
Analyzes both binetflow files and botnet PCAP files to capture all relevant traffic.
Only includes botnet, command and control, and normal traffic (excludes background).
"""

import os
import sys
import logging
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Dict, Any, Optional

from ctu13_dataset_analyser.core.analyser import PcapAnalyser
from ctu13_dataset_analyser.utils.binetflow_parser import BinetflowParser
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


def process_pcap_file(pcap_file: str, scenario: str) -> List[Dict[str, Any]]:
    """Process a single PCAP file and return session metrics."""
    logger.info(f"Processing PCAP file: {pcap_file} from scenario {scenario}")

    results = []
    analyser = PcapAnalyser()

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

                # Set label based on filename pattern
                filename = os.path.basename(pcap_file).lower()

                # Most botnet-capture files contain botnet traffic
                if "botnet" in filename:
                    if (
                        "cnc" in filename
                        or "c&c" in filename
                        or "cc" in filename
                        or "command" in filename
                    ):
                        metrics["session_label"] = "command-and-control"
                        metrics["is_cc"] = 1
                        metrics["is_botnet"] = 0
                        metrics["is_normal"] = 0
                        metrics["is_background"] = 0
                    else:
                        metrics["session_label"] = "botnet"
                        metrics["is_botnet"] = 1
                        metrics["is_cc"] = 0
                        metrics["is_normal"] = 0
                        metrics["is_background"] = 0
                elif "normal" in filename:
                    metrics["session_label"] = "normal"
                    metrics["is_normal"] = 1
                    metrics["is_botnet"] = 0
                    metrics["is_cc"] = 0
                    metrics["is_background"] = 0
                else:
                    # Skip background traffic
                    continue

                results.append(metrics)

        logger.info(f"Extracted {len(results)} sessions from {pcap_file}")
        return results

    except Exception as e:
        logger.error(f"Error processing PCAP file {pcap_file}: {e}")
        return []


def process_binetflow_file(
    scenario_dir: str,
    output_file: str,
    fieldnames: List[str],
    filter_proto: Optional[str] = None,
    filter_label: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Process a binetflow file from a CTU-13 scenario directory and write results to CSV.
    Only includes normal traffic (not botnet, C&C, or background).

    Args:
        scenario_dir: Path to the scenario directory
        output_file: Path to the output CSV file
        fieldnames: CSV field names
        filter_proto: Optional protocol filter (TCP, UDP, ICMP, ALL)
        filter_label: Optional label filter (botnet, normal, cc, ALL)

    Returns:
        List of session metrics dictionaries (for sampling purposes)
    """
    logger.info(
        f"Processing binetflow file for normal traffic from directory: {scenario_dir}"
    )
    scenario = os.path.basename(scenario_dir)

    # Create parser
    # Don't force the filter_label to "normal" so we get all traffic types
    parser = BinetflowParser(filter_proto, filter_label)

    # Find binetflow file
    binetflow_path = parser.find_binetflow_file(scenario_dir)
    if not binetflow_path:
        logger.warning(f"No binetflow file found in {scenario_dir}")
        return []

    # Process the binetflow file
    session_count = 0
    batch_size = 10000
    current_batch = []
    sample_results = []  # For returning sample metrics

    for metrics in parser.parse_binetflow_file(binetflow_path, scenario):
        # Process all traffic types (filtering already done in parser)
        current_batch.append(metrics)
        session_count += 1

        # Save first few for sampling
        if len(sample_results) < 10:
            sample_results.append(metrics)

        # Write batch when it reaches the threshold
        if len(current_batch) >= batch_size:
            append_results_to_csv(current_batch, output_file, fieldnames)
            logger.info(f"Processed {session_count} sessions from scenario {scenario}")
            current_batch = []

    # Write any remaining sessions
    if current_batch:
        append_results_to_csv(current_batch, output_file, fieldnames)

    logger.info(
        f"Extracted {session_count} sessions from binetflow in scenario {scenario}"
    )
    return sample_results


def process_pcap_files(
    scenario_dir: str,
    output_file: str,
    fieldnames: List[str],
    filter_proto: Optional[str] = None,
    filter_label: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Process PCAP files from a scenario directory to extract botnet/C&C traffic.

    Args:
        scenario_dir: Path to the scenario directory
        output_file: Path to the output CSV file
        fieldnames: CSV field names
        filter_proto: Optional protocol filter (TCP, UDP, ICMP, ALL)
        filter_label: Optional label filter (botnet, normal, cc, ALL)

    Returns:
        List of session metrics dictionaries (for sampling purposes)
    """
    logger.info(
        f"Processing PCAP files for botnet/C&C traffic from directory: {scenario_dir}"
    )
    scenario = os.path.basename(scenario_dir)

    # Find all PCAP files with botnet traffic
    pcap_files = []
    for file in os.listdir(scenario_dir):
        if file.endswith(".pcap") and "botnet" in file.lower():
            pcap_files.append(os.path.join(scenario_dir, file))

    if not pcap_files:
        logger.warning(f"No botnet PCAP files found in {scenario_dir}")
        return []

    # Process each PCAP file
    all_results = []
    sample_results = []  # For returning sample metrics

    for pcap_file in pcap_files:
        # Process the file and get session metrics
        session_results = process_pcap_file(pcap_file, scenario)

        # Apply protocol filter if specified
        if filter_proto and filter_proto != "ALL":
            session_results = [
                result
                for result in session_results
                if result.get("proto") == filter_proto
            ]

        # Apply label filter if specified
        if filter_label and filter_label != "ALL":
            if filter_label == "cc":
                session_results = [
                    result
                    for result in session_results
                    if result.get("session_label") == "command-and-control"
                ]
            elif filter_label == "botnet":
                session_results = [
                    result
                    for result in session_results
                    if result.get("session_label") == "botnet"
                ]
            elif filter_label == "normal":
                session_results = [
                    result
                    for result in session_results
                    if result.get("session_label") == "normal"
                ]

        # Write results to CSV
        if session_results:
            append_results_to_csv(session_results, output_file, fieldnames)
            all_results.extend(session_results)

            # Save first few for sampling
            if len(sample_results) < 10:
                sample_results.extend(session_results[: 10 - len(sample_results)])

    logger.info(
        f"Extracted {len(all_results)} botnet/C&C sessions from PCAP files in scenario {scenario}"
    )
    return sample_results


def process_scenario(
    scenario_dir: str,
    output_file: str,
    fieldnames: List[str],
    filter_proto: Optional[str] = None,
    filter_label: Optional[str] = None,
) -> None:
    """
    Process a single CTU-13 scenario directory and write results to CSV.
    Combines analysis of binetflow files (for all traffic types) and PCAP files (for botnet/C&C).

    Args:
        scenario_dir: Path to the scenario directory
        output_file: Path to the output CSV file
        fieldnames: CSV field names
        filter_proto: Optional protocol filter (TCP, UDP, ICMP, ALL)
        filter_label: Optional label filter (botnet, normal, cc, ALL)
    """
    logger.info(f"Processing scenario directory: {scenario_dir}")
    scenario = os.path.basename(scenario_dir)

    # Process binetflow file for all traffic types (filtering done in parser)
    process_binetflow_file(
        scenario_dir, output_file, fieldnames, filter_proto, filter_label
    )

    # Process PCAP files for botnet and C&C traffic
    # This ensures we don't miss botnet/C&C sessions that might not be in binetflow
    if (
        not filter_label
        or filter_label == "ALL"
        or filter_label == "botnet"
        or filter_label == "cc"
    ):
        process_pcap_files(
            scenario_dir, output_file, fieldnames, filter_proto, filter_label
        )

    logger.info(f"Completed scenario {scenario}")


def process_scenario_wrapper(args):
    """Wrapper for process_scenario to unpack arguments for ProcessPoolExecutor."""
    scenario_dir, output_file, fieldnames, filter_proto, filter_label = args
    return process_scenario(
        scenario_dir, output_file, fieldnames, filter_proto, filter_label
    )


def get_sample_data(dataset_root: str, scenarios: List[str]) -> List[Dict[str, Any]]:
    """
    Get sample session data for determining fieldnames.
    Tries to get a combination of botnet, C&C, and normal traffic.

    Args:
        dataset_root: Path to the CTU-13 dataset root
        scenarios: List of scenario directories to check

    Returns:
        List of session metrics dictionaries
    """
    sample_results = []

    # Try first scenario
    if scenarios:
        scenario_dir = os.path.join(dataset_root, scenarios[0])

        # Try to get botnet/C&C traffic from PCAP
        pcap_samples = []
        for file in os.listdir(scenario_dir):
            if file.endswith(".pcap") and "botnet" in file.lower():
                pcap_file = os.path.join(scenario_dir, file)
                pcap_samples = process_pcap_file(pcap_file, scenarios[0])
                if pcap_samples:
                    sample_results.extend(pcap_samples[:5])
                    break

        # Try to get normal traffic from binetflow
        parser = BinetflowParser(filter_label="normal")
        binetflow_path = parser.find_binetflow_file(scenario_dir)

        if binetflow_path:
            count = 0
            for metrics in parser.parse_binetflow_file(binetflow_path, scenarios[0]):
                if metrics.get("session_label") == "normal":
                    sample_results.append(metrics)
                    count += 1
                    if count >= 5:
                        break

    # If we still need more samples, try other scenarios
    if len(sample_results) < 5 and len(scenarios) > 1:
        for scenario in scenarios[1:]:
            scenario_dir = os.path.join(dataset_root, scenario)

            # Try PCAP files
            for file in os.listdir(scenario_dir):
                if file.endswith(".pcap") and "botnet" in file.lower():
                    pcap_file = os.path.join(scenario_dir, file)
                    more_samples = process_pcap_file(pcap_file, scenario)
                    if more_samples:
                        sample_results.extend(more_samples[: 10 - len(sample_results)])
                        if len(sample_results) >= 10:
                            return sample_results

    return sample_results


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

    # Display distribution statistics if requested
    if args.show_stats:
        logger.info("Generating dataset statistics (excluding background traffic)...")
        parser = BinetflowParser()
        parser.generate_dataset_statistics(args.dataset_root)
        if not args.process_data:
            logger.info("Statistics generated. Exiting without processing data.")
            return

    # Determine which scenarios to process
    scenarios = []
    if args.scenarios:
        for scenario in args.scenarios:
            scenario_dir = scenario
            if not os.path.isdir(scenario_dir):
                scenario_dir = os.path.join(args.dataset_root, scenario)

            if os.path.isdir(scenario_dir):
                scenarios.append(scenario)
            else:
                logger.warning(f"Scenario directory not found: {scenario_dir}")
    else:
        # Process all scenario directories
        for scenario in os.listdir(args.dataset_root):
            scenario_dir = os.path.join(args.dataset_root, scenario)
            if os.path.isdir(scenario_dir) and scenario.isdigit():
                scenarios.append(scenario)

    if not scenarios:
        logger.error("No valid scenario directories found")
        sys.exit(1)

    logger.info(f"Will process {len(scenarios)} scenario directories")

    # Get sample data for determining field names
    sample_results = get_sample_data(args.dataset_root, scenarios)

    if not sample_results:
        logger.error("Could not get any sample data from the specified scenarios")
        sys.exit(1)

    # Apply filters to sample if needed
    if args.filter_proto != "ALL":
        sample_results = [
            r for r in sample_results if r.get("proto") == args.filter_proto
        ]

    if args.filter_label != "ALL":
        if args.filter_label == "cc":
            sample_results = [
                r
                for r in sample_results
                if r.get("session_label") == "command-and-control"
            ]
        elif args.filter_label == "botnet":
            sample_results = [
                r for r in sample_results if r.get("session_label") == "botnet"
            ]
        elif args.filter_label == "normal":
            sample_results = [
                r for r in sample_results if r.get("session_label") == "normal"
            ]

    if not sample_results:
        logger.error("Could not determine CSV fields after applying filters")
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
        scenario_args = []
        for scenario in scenarios:
            scenario_dir = os.path.join(args.dataset_root, scenario)
            if os.path.isdir(scenario_dir):
                scenario_args.append(
                    (
                        scenario_dir,
                        args.output,
                        fieldnames,
                        args.filter_proto,
                        args.filter_label,
                    )
                )

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
                scenario_dir = os.path.join(args.dataset_root, scenario)
                process_scenario(
                    scenario_dir,
                    args.output,
                    fieldnames,
                    args.filter_proto,
                    args.filter_label,
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
