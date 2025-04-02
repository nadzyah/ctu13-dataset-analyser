# CTU-13 Dataset Analyser

A Python tool for analysing PCAP files from the CTU-13 botnet dataset. This tool extracts
network sessions from PCAP files, calculates various traffic metrics, and labels the
traffic based on botnet activity.

## Features

- Extracts bidirectional network sessions from PCAP files
- Calculates comprehensive traffic metrics for each session:
  - Packet counts (sent/received)
  - Packet size statistics (min, max, average, variance)
  - Time interval measurements between packets
  - Session duration
- Automatically labels traffic as botnet, normal, command & control, or background
- Supports concurrent processing of multiple scenarios
- Outputs results to CSV for further analysis

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/nadzyah/ctu13-dataset-analyser.git
cd ctu13-dataset-analyser
poetry install
```

## Requirements

- Directory with the extracted `CTU-13-Dataset` from [the `tar.bz2`
  archive](https://www.stratosphereips.org/datasets-ctu13).
- Python (>=3.11)
- poetry (>=2.1.2)

## Usage

### Basic Usage

```bash
poetry run ./main.py /path/to/CTU-13-Dataset
```

This will analyse all scenarios in the dataset and save the results to
`session_metrics.csv` in the current directory.

### Advanced Usage

```bash
# Process specific scenarios
poetry run ./main.py /path/to/CTU-13-Dataset --scenarios 1 4 10

# Write to a custom output file
poetry run ./main.py /path/to/CTU-13-Dataset --output my_results.csv

# Use 8 parallel workers for faster processing
poetry run ./main.py /path/to/CTU-13-Dataset --max-workers 8

# Filter by protocol
poetry run ./main.py /path/to/CTU-13-Dataset --filter-proto TCP

# Enable verbose logging
poetry run ./main.py /path/to/CTU-13-Dataset --verbose
```

## Output Format

The analyser outputs a CSV file with the following metrics for each session:

| Field | Description |
|-------|-------------|
| src_ip | Source IP address |
| dst_ip | Destination IP address |
| src_port | Source port |
| dst_port | Destination port |
| proto | Protocol (TCP, UDP, ICMP) |
| session_label | Classification (botnet, normal, command-and-control, background) |
| spc | Number of packets sent |
| rpc | Number of packets received |
| tss | Total size of sent packets (bytes) |
| tsr | Total size of received packets (bytes) |
| smin | Minimum size of sent packets |
| smax | Maximum size of sent packets |
| rmin | Minimum size of received packets |
| rmax | Maximum size of received packets |
| savg | Average size of sent packets |
| ravg | Average size of received packets |
| svar | Variance of sent packet sizes |
| rvar | Variance of received packet sizes |
| sintmin | Minimum interval between sent packets |
| sintmax | Maximum interval between sent packets |
| sintavg | Average interval between sent packets |
| sintvar | Variance of intervals between sent packets |
| rintmin | Minimum interval between received packets |
| rintmax | Maximum interval between received packets |
| rintavg | Average interval between received packets |
| rintvar | Variance of intervals between received packets |
| time | Session duration |
| scenario | Scenario number |
| pcap_file | Source PCAP filename |

## Project Structure

```
ctu13_dataset_analyser/
├── core/                  # Core functionality
│   ├── session.py         # Session class for metrics calculation
│   └── analyser.py        # PCAP file analysis
├── utils/                 # Utility functions
│   ├── ip_extractor.py    # Extract known IPs from README files
│   ├── packet_parser.py   # Packet parsing utilities
│   └── csv_writer.py      # CSV output handling
├── cli_arguments.py       # Command-line interface
└── main.py                # The main script
```

## About the CTU-13 Dataset

The CTU-13 dataset consists of 13 different malware capture scenarios created by the
Stratosphere Lab at the Czech Technical University. Each scenario contains captured
traffic from a specific malware, with mixed botnet and normal traffic.

The dataset includes labelled information about:
- Botnet traffic
- Normal traffic
- Background traffic
- Command & Control (C&C) channels

For more information about the dataset, visit:
https://www.stratosphereips.org/datasets-ctu13

## Acknowledgements

This tool was developed for analysing the CTU-13 dataset from the Stratosphere Lab at
Czech Technical University, Prague, Czech Republic.
