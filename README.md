# Network Analysis Port Scanner Tool

This Python script is designed for comprehensive network analysis, offering functionalities such as network speed testing, Wi-Fi signal strength assessment, open port scanning, and system information reporting.

## Features

- **Network Speed Testing**: Utilizes `speedtest-cli` for accurate internet bandwidth testing.
- **Wi-Fi Signal Strength Measurement**: Assesses signal strength for both Linux and Windows systems.
- **Open Port Scanning**: Scans and describes well-known ports to help identify network vulnerabilities.
- **System Information Reporting**: Captures detailed information about the system's hardware and OS.
- **Customizable Analysis**: Allows users to tailor the analysis with specific options and outputs.

## Prerequisites

The script requires Python 3.x and several dependencies:

- `speedtest-cli`: Tests internet bandwidth using speedtest.net.
- `psutil`: Accesses system details and utilities.

It also uses standard Python libraries such as `os`, `socket`, `argparse`, `sys`, `platform`, `subprocess`, `logging`, and `time`.

Install the necessary packages using pip:

```bash
pip install speedtest-cli psutil
