"""
Functions for extracting known IP addresses from CTU-13 dataset README files.
Handles various CTU-13 README formats.
"""

import os
import re
import logging
from typing import Set, Tuple, List
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


def extract_known_ips(dataset_root: str) -> Tuple[Set[str], Set[str]]:
    """
    Extract known botnet and normal IPs from README files.

    Args:
        dataset_root: Path to the root directory of the CTU-13 dataset

    Returns:
        Tuple containing (botnet_ips, normal_ips)
    """
    botnet_ips = set()
    normal_ips = set()

    # IP pattern for validation
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    # Iterate through scenario directories
    for scenario in os.listdir(dataset_root):
        scenario_dir = os.path.join(dataset_root, scenario)

        if not os.path.isdir(scenario_dir):
            continue

        # Try to parse README file
        readme_path = find_readme_file(scenario_dir)
        if not readme_path:
            continue

        try:
            with open(readme_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

                # Check if this is an HTML README
                if (
                    readme_path.lower().endswith(".html")
                    or content.strip().startswith("<!DOCTYPE")
                    or content.strip().startswith("<html")
                ):
                    # Parse HTML content
                    scenario_botnet_ips, scenario_normal_ips = extract_ips_from_html(
                        content, ip_pattern
                    )
                else:
                    # Parse plain text content
                    scenario_botnet_ips, scenario_normal_ips = extract_ips_from_text(
                        content, ip_pattern
                    )

                botnet_ips.update(scenario_botnet_ips)
                normal_ips.update(scenario_normal_ips)

                logger.info(
                    f"From {readme_path}: Found {len(scenario_botnet_ips)} botnet IPs and {len(scenario_normal_ips)} normal IPs"
                )

        except Exception as e:
            logger.warning(f"Error parsing README in {scenario_dir}: {e}")

    # Remove any IPs that appear in both sets (should be considered botnet)
    normal_ips -= botnet_ips

    logger.info(
        f"Total: Extracted {len(botnet_ips)} botnet IPs and {len(normal_ips)} normal IPs"
    )
    return botnet_ips, normal_ips


def find_readme_file(directory: str) -> str:
    """Find README file in various formats."""
    potential_names = ["README", "README.html", "README.txt", "readme"]

    for name in potential_names:
        path = os.path.join(directory, name)
        if os.path.exists(path):
            return path

    return ""


def extract_ips_from_html(
    content: str, ip_pattern: re.Pattern
) -> Tuple[Set[str], Set[str]]:
    """
    Extract botnet and normal IPs from HTML README content.

    Args:
        content: HTML content of README file
        ip_pattern: Regular expression pattern for validating IP addresses

    Returns:
        Tuple containing (botnet_ips, normal_ips)
    """
    try:
        # Parse HTML
        soup = BeautifulSoup(content, "html.parser")

        # Extract text content
        text_content = soup.get_text()

        # Fall back to text extraction
        return extract_ips_from_text(text_content, ip_pattern)

    except Exception as e:
        logger.warning(f"Error parsing HTML: {e}")
        # Try to extract IPs using regex as fallback
        return extract_ips_using_regex(content, ip_pattern)


def extract_ips_from_text(
    content: str, ip_pattern: re.Pattern
) -> Tuple[Set[str], Set[str]]:
    """
    Extract botnet and normal IPs from plain text README content.

    Args:
        content: Plain text content of README file
        ip_pattern: Regular expression pattern for validating IP addresses

    Returns:
        Tuple containing (botnet_ips, normal_ips)
    """
    botnet_ips = set()
    normal_ips = set()

    lines = content.splitlines()
    extract_botnet_ips_from_lines(lines, botnet_ips, ip_pattern)
    extract_normal_ips_from_lines(lines, normal_ips, ip_pattern)

    return botnet_ips, normal_ips


def extract_botnet_ips_from_lines(
    lines: List[str], botnet_ips: Set[str], ip_pattern: re.Pattern
) -> None:
    """
    Extract botnet IPs from lines of text.

    Args:
        lines: Lines of text from README file
        botnet_ips: Set to add extracted botnet IPs to
        ip_pattern: Regular expression pattern for validating IP addresses
    """
    # Various patterns for infected machine sections
    infected_section_patterns = [r"infected\s+machines", r"label:\s*botnet"]

    in_infected_section = False

    for i, line in enumerate(lines):
        line_lower = line.lower()

        # Check if we're entering infected machines section
        if not in_infected_section:
            for pattern in infected_section_patterns:
                if re.search(pattern, line_lower):
                    in_infected_section = True
                    break

        # Check if we're exiting infected machines section (new section header)
        if (
            in_infected_section
            and re.match(r"^[A-Z].*:$", line.strip())
            and "ip:" not in line_lower
        ):
            in_infected_section = False

        # Look for IP addresses in current line
        if in_infected_section or "label: botnet" in line_lower:
            # Extract IPs with common formats
            ip_candidates = []

            # Format: IP: 123.45.67.89
            ip_match = re.search(
                r"IP:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line, re.IGNORECASE
            )
            if ip_match:
                ip_candidates.append(ip_match.group(1))

            # Format: Windows XP Name: XXX, IP: 123.45.67.89
            ip_match = re.search(
                r"IP:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line, re.IGNORECASE
            )
            if ip_match:
                ip_candidates.append(ip_match.group(1))

            # Add valid IPs to the set
            for ip in ip_candidates:
                if ip_pattern.match(ip):
                    botnet_ips.add(ip)

        # Always catch any line that explicitly mentions botnet
        if "botnet" in line_lower:
            all_ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line)
            for ip in all_ips:
                if ip_pattern.match(ip):
                    botnet_ips.add(ip)


def extract_normal_ips_from_lines(
    lines: List[str], normal_ips: Set[str], ip_pattern: re.Pattern
) -> None:
    """
    Extract normal/legitimate IPs from lines of text.

    Args:
        lines: Lines of text from README file
        normal_ips: Set to add extracted normal IPs to
        ip_pattern: Regular expression pattern for validating IP addresses
    """
    # Look for sections describing legitimate/normal traffic
    normal_keywords = ["normal", "legitimate", "clean", "not infected"]

    for i, line in enumerate(lines):
        line_lower = line.lower()

        # Check if line mentions normal/legitimate traffic and contains an IP
        if any(keyword in line_lower for keyword in normal_keywords) and re.search(
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line
        ):
            # Extract all IPs from this line
            all_ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line)

            for ip in all_ips:
                if ip_pattern.match(ip):
                    normal_ips.add(ip)

            # Also look ahead a few lines for additional IPs
            for j in range(i + 1, min(i + 5, len(lines))):
                next_line = lines[j]
                if any(keyword in next_line.lower() for keyword in normal_keywords):
                    more_ips = re.findall(
                        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", next_line
                    )
                    for ip in more_ips:
                        if ip_pattern.match(ip):
                            normal_ips.add(ip)


def extract_ips_using_regex(
    content: str, ip_pattern: re.Pattern
) -> Tuple[Set[str], Set[str]]:
    """
    Extract IPs using regex as a fallback method.

    Args:
        content: Content of README file
        ip_pattern: Regular expression pattern for validating IP addresses

    Returns:
        Tuple containing (botnet_ips, normal_ips)
    """
    botnet_ips = set()
    normal_ips = set()

    # Find all IP addresses
    all_ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", content)

    # Categorize IPs based on context
    for ip in all_ips:
        if not ip_pattern.match(ip):
            continue

        # Look for botnet indicators near the IP
        ip_context = extract_context(content, ip, 100)  # Get 100 chars before and after
        ip_context_lower = ip_context.lower()

        if (
            "botnet" in ip_context_lower
            or "infected" in ip_context_lower
            or "label: botnet" in ip_context_lower
        ):
            botnet_ips.add(ip)
        elif (
            "normal" in ip_context_lower
            or "legitimate" in ip_context_lower
            or "clean" in ip_context_lower
            or "not infected" in ip_context_lower
        ):
            normal_ips.add(ip)

    return botnet_ips, normal_ips


def extract_context(text: str, target: str, context_size: int) -> str:
    """
    Extract text around a target string.

    Args:
        text: Full text to search in
        target: Target string to find
        context_size: Number of characters to include before and after

    Returns:
        String containing the target and surrounding context
    """
    index = text.find(target)
    if index == -1:
        return ""

    start = max(0, index - context_size)
    end = min(len(text), index + len(target) + context_size)

    return text[start:end]
