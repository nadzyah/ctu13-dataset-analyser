#!/usr/bin/env python3
"""
Main entry point for the CTU-13 PCAP Analyser.
"""

import os
import sys
import logging
from concurrent.futures import ProcessPoolExecutor
from typing import List, Dict, Any

from ctu13_dataset_analyser.core.analyser import PcapAnalyser
from ctu13_dataset_analyser.utils.ip_extractor import extract_known_ips
from ctu13_dataset_analyser.utils.csv_writer import write_results_to_csv
from ctu13_dataset_analyser.cli_arguments import parse_arguments

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("ctu13_dataset_analyser")


def process_scenario(scenario_dir: str, botnet_ips, normal_ips) -> List[Dict[str, Any]]:
    """Process a single CTU-13 scenario directory."""
    logger.info(f"Processing scenario directory: {scenario_dir}")

    results = []
    analyser = PcapAnalyser(botnet_ips, normal_ips)

    # Find all PCAP files in the directory
    pcap_files = []
    for file in os.listdir(scenario_dir):
        if file.endswith(".pcap"):
            pcap_files.append(os.path.join(scenario_dir, file))

    if not pcap_files:
        logger.warning(f"No PCAP files found in {scenario_dir}")
        return []

    for pcap_file in pcap_files:
        sessions = analyser.process_pcap_file(pcap_file)

        # Calculate metrics for each session
        for session in sessions.values():
            metrics = session.calculate_metrics()
            if metrics:  # Skip empty metrics (non-bidirectional sessions)
                metrics["scenario"] = os.path.basename(scenario_dir)
                metrics["pcap_file"] = os.path.basename(pcap_file)
                results.append(metrics)

    logger.info(f"Processed {len(results)} sessions from scenario {scenario_dir}")
    return results


def run() -> None:
    """Main function to run the PCAP analyser."""
    args = parse_arguments()

    if not os.path.isdir(args.dataset_root):
        logger.error(f"Dataset root directory not found: {args.dataset_root}")
        sys.exit(1)

    botnet_ips, normal_ips = extract_known_ips(args.dataset_root)

    scenarios = []
    if args.scenarios:
        for scenario in args.scenarios:
            scenario_dir = os.path.join(args.dataset_root, scenario)
            if os.path.isdir(scenario_dir):
                scenarios.append(scenario_dir)
            else:
                logger.warning(f"Scenario directory not found: {scenario_dir}")
    else:
        for scenario in os.listdir(args.dataset_root):
            scenario_dir = os.path.join(args.dataset_root, scenario)
            if os.path.isdir(scenario_dir) and scenario.isdigit():
                scenarios.append(scenario_dir)

    if not scenarios:
        logger.error("No valid scenario directories found")
        sys.exit(1)

    logger.info(f"Processing {len(scenarios)} scenario directories")

    # Process scenarios (potentially in parallel)
    all_results = []

    if args.max_workers > 1:
        with ProcessPoolExecutor(max_workers=args.max_workers) as executor:
            futures = {
                executor.submit(
                    process_scenario, scenario, botnet_ips, normal_ips
                ): scenario
                for scenario in scenarios
            }

            for future in futures:
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    logger.error(f"Error processing scenario {futures[future]}: {e}")
    else:
        # Process scenarios sequentially
        for scenario in scenarios:
            try:
                results = process_scenario(scenario, botnet_ips, normal_ips)
                all_results.extend(results)
            except Exception as e:
                logger.error(f"Error processing scenario {scenario}: {e}")

    # Write results to CSV
    write_results_to_csv(all_results, args.output)
    logger.info(f"Analysis complete. Results written to {args.output}")


if __name__ == "__main__":
    run()
