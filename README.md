# CTU-13 Dataset Analyser

A Python tool for analysing the CTU-13 botnet dataset by extracting
network sessions from both binetflow and PCAP files. This tool
calculates comprehensive traffic metrics and accurately labels the
traffic as botnet, normal, or command & control.

## Features

- **Combined Analysis Approach**:
  - Processes binetflow files for normal traffic
  - Processes PCAP files for botnet and command & control traffic
  - Excludes background traffic for focused analysis

- **Extracts Bidirectional Network Sessions**:
  - Identifies bidirectional sessions with traffic in both directions
  - Handles explicitly marked bidirectional flows with "<->" direction

- **Calculates Comprehensive Traffic Metrics**:
  - Packet counts (sent/received)
  - Packet size statistics (min, max, average, variance)
  - Time interval measurements between packets
  - Session duration

- **Intelligent Traffic Classification**:
  - Automatically labels sessions as botnet, normal, or command &
    control
  - Uses multiple indicators for accurate classification
  - Handles various naming patterns in the dataset

- **High Performance**:
  - Supports concurrent processing of multiple scenarios
  - Memory-optimized for handling large files
  - Incremental processing with batch writing

- **Enhanced Usability**:
  - Outputs results to CSV for further analysis
  - Provides dataset statistics
  - Supports filtering by protocol and traffic type

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/nadzyah/ctu13-dataset-analyser.git
cd ctu13-dataset-analyser
poetry install
```

## Requirements

- Directory with the extracted `CTU-13-Dataset` from [the `tar.bz2`
  archive](https://www.stratosphereips.org/datasets-ctu13)
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

# Filter by traffic type (excluding background)
poetry run ./main.py /path/to/CTU-13-Dataset --filter-label botnet

# Show dataset statistics without processing
poetry run ./main.py /path/to/CTU-13-Dataset --show-stats --no-process-data

# Enable verbose logging
poetry run ./main.py /path/to/CTU-13-Dataset --verbose
```

## Output Format

The analyser outputs a CSV file with the following metrics for each
session:

| Field | Description |
|-------|-------------|
| scenario | Scenario number |
| pcap_file | Source PCAP filename (if from PCAP) |
| binetflow_file | Source binetflow filename (if from binetflow) |
| src_ip | Source/client IP address |
| dst_ip | Destination/server IP address |
| src_port | Source port |
| dst_port | Destination port |
| proto | Protocol (TCP, UDP, ICMP) |
| start_time | Session start time |
| session_label | Classification (botnet, normal, command-and-control) |
| is_botnet | Flag indicating botnet traffic (1 or 0) |
| is_normal | Flag indicating normal traffic (1 or 0) |
| is_cc | Flag indicating command & control traffic (1 or 0) |
| original_label | Original label from the dataset (for binetflow sources) |
| spc | Number of packets sent |
| rpc | Number of packets received |
| time | Session duration |
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
| state | TCP connection state (for TCP sessions) |

## Project Structure

```
ctu13_dataset_analyser/
├── core/                  # Core functionality
│   ├── session.py         # Session class for metrics calculation
│   └── analyser.py        # PCAP file analysis
├── utils/                 # Utility functions
│   ├── binetflow_parser.py # Binetflow file processing
│   ├── packet_parser.py   # Packet parsing utilities
│   └── csv_writer.py      # CSV output handling
├── cli_arguments.py       # Command-line interface
└── main.py                # The main script
```

## Data Sources in CTU-13

The CTU-13 dataset provides two main sources of data:

1. **Binetflow Files**: CSV-formatted files containing pre-processed
   network flow records
   - Contains normal, botnet, and background traffic
   - Labelled with flow classification
   - More compact but less detailed

2. **PCAP Files**: Raw packet capture files
   - Separate files for botnet traffic
   - Contains detailed packet-level information
   - Enables more accurate metrics calculation

This tool combines both sources to provide comprehensive analysis
while maintaining efficiency.

## About the CTU-13 Dataset

The CTU-13 dataset consists of 13 different malware capture scenarios
created by the Stratosphere Lab at the Czech Technical
University. Each scenario contains captured traffic from a specific
malware, with mixed botnet and normal traffic.

The dataset includes labelled information about:
- Botnet traffic
- Normal traffic
- Background traffic
- Command & Control (C&C) channels

For more information about the dataset, visit:
https://www.stratosphereips.org/datasets-ctu13

## Acknowledgements

This tool was developed for analysing the CTU-13 dataset from the
Stratosphere Lab at Czech Technical University, Prague, Czech
Republic.
