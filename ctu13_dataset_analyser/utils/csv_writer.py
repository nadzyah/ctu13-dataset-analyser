"""
Functions for writing analysis results to CSV files.
Includes support for binetflow-derived sessions.
"""

import csv
import logging
import os
import threading
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# File lock to prevent concurrent writes to the same file
csv_file_lock = threading.Lock()


def initialize_csv_file(output_file: str, fieldnames: List[str]) -> None:
    """
    Initialize a CSV file with headers. Creates the file if it doesn't exist.

    Args:
        output_file: Path to the output CSV file
        fieldnames: List of field names to include as CSV headers
    """
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)

    with csv_file_lock:
        # Check if file exists and is empty or needs to be created
        file_exists = os.path.exists(output_file)
        file_empty = file_exists and os.path.getsize(output_file) == 0

        if not file_exists or file_empty:
            try:
                with open(output_file, "w", newline="") as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                logger.info(f"Initialized CSV file: {output_file}")
            except Exception as e:
                logger.error(f"Error initializing CSV file {output_file}: {e}")
                raise


def get_prioritized_fieldnames(results: List[Dict[str, Any]]) -> List[str]:
    """
    Generate a sensibly ordered list of fieldnames from sample results.

    Args:
        results: Sample results to extract field names from

    Returns:
        List of field names in a prioritized order
    """
    if not results:
        return []

    # Get all possible fields from the results
    all_fieldnames = set()
    for result in results:
        all_fieldnames.update(result.keys())

    # Create a sensible order for fields
    prioritized_fields = [
        # Session identification
        "scenario",
        "pcap_file",
        "binetflow_file",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "proto",
        "start_time",
        # Session labels
        "session_label",
        "is_botnet",
        "is_normal",
        "is_cc",
        "is_background",
        "original_label",
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
        # Additional state information
        "state",
    ]

    # Start with prioritized fields that are actually in results
    fieldnames = [f for f in prioritized_fields if f in all_fieldnames]

    # Add any remaining fields alphabetically
    remaining_fields = sorted(all_fieldnames - set(fieldnames))
    fieldnames.extend(remaining_fields)

    return fieldnames


def append_results_to_csv(
    results: List[Dict[str, Any]], output_file: str, fieldnames: List[str]
) -> None:
    """
    Append analysis results to a CSV file with thread safety.

    Args:
        results: List of dictionaries with analysis results
        output_file: Path to the CSV file to append to
        fieldnames: List of field names in the CSV
    """
    if not results:
        logger.warning("No results to append to CSV")
        return

    with csv_file_lock:
        try:
            with open(output_file, "a", newline="") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                for result in results:
                    # Only include fields that are in fieldnames
                    filtered_result = {
                        k: v for k, v in result.items() if k in fieldnames
                    }
                    writer.writerow(filtered_result)

            logger.info(
                f"Successfully appended {len(results)} records to {output_file}"
            )

        except Exception as e:
            logger.error(f"Error appending to CSV file {output_file}: {e}")
