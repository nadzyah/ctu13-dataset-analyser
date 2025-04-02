"""
Functions for writing analysis results to CSV files.
"""

import csv
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


def write_results_to_csv(
    results: List[Dict[str, Any]],
    output_file: str,
    fieldnames: Optional[List[str]] = None,
) -> None:
    """
    Write analysis results to a CSV file.

    Args:
        results: List of dictionaries with analysis results
        output_file: Path to the output CSV file
        fieldnames: Optional list of field names to include in the CSV (and their order)
    """
    if not results:
        logger.warning("No results to write to CSV")
        return

    try:
        # Determine fieldnames if not provided
        if fieldnames is None:
            # Get all possible fields from the results
            all_fieldnames = set()
            for result in results:
                all_fieldnames.update(result.keys())

            # Create a sensible order for fields
            prioritized_fields = [
                # Session identification
                "scenario",
                "pcap_file",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "proto",
                # Session labels
                "session_label",
                "is_botnet",
                "is_normal",
                "is_cc",
                "is_background",
                # Basic metrics
                "spc",
                "rpc",
                "time",
                # Size metrics
                "tss",
                "tsr",
                "smin",
                "smax",
                "rmin",
                "rmax",
                "savg",
                "ravg",
                "svar",
                "rvar",
                # Time interval metrics
                "sintmin",
                "sintmax",
                "sintavg",
                "sintvar",
                "rintmin",
                "rintmax",
                "rintavg",
                "rintvar",
            ]

            # Start with prioritized fields that are actually in results
            fieldnames = [f for f in prioritized_fields if f in all_fieldnames]

            # Add any remaining fields alphabetically
            remaining_fields = sorted(all_fieldnames - set(fieldnames))
            fieldnames.extend(remaining_fields)

        with open(output_file, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for result in results:
                # Only include fields that are in fieldnames
                filtered_result = {k: v for k, v in result.items() if k in fieldnames}
                writer.writerow(filtered_result)

        logger.info(f"Successfully wrote {len(results)} records to {output_file}")

    except Exception as e:
        logger.error(f"Error writing to CSV file {output_file}: {e}")


def append_results_to_csv(
    results: List[Dict[str, Any]], output_file: str, fieldnames: List[str]
) -> None:
    """
    Append analysis results to an existing CSV file.

    Args:
        results: List of dictionaries with analysis results
        output_file: Path to the CSV file to append to
        fieldnames: List of field names in the CSV
    """
    if not results:
        logger.warning("No results to append to CSV")
        return

    try:
        with open(output_file, "a", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            for result in results:
                # Only include fields that are in fieldnames
                filtered_result = {k: v for k, v in result.items() if k in fieldnames}
                writer.writerow(filtered_result)

        logger.info(f"Successfully appended {len(results)} records to {output_file}")

    except Exception as e:
        logger.error(f"Error appending to CSV file {output_file}: {e}")
