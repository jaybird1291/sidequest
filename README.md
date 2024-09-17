# Side Quest
_École 2600 - Promo 2026 - Année 2023-2024_

Our Side Quest is a collaborative student project designed to provide a powerful toolkit for forensic analysis and malware analysis. This repository contains two sub-projects that focus on different aspects of investigation:
- **Forensic Analysis**: Tools for analyzing network traffic captured in PCAP files.
- **Malware Analysis**: Tools for dissecting binary files to uncover hidden information and detect malicious characteristics.

# Mains features
## Forensic Analysis
- Analyze PCAP files to gather data on IP addresses, network protocols, and traffic patterns.
- Extract files from network captures and compute their hashes.
- Integrate with VirusTotal for file reputation analysis.
- Utilize tools like tshark and scapy for in-depth packet inspection.
## Malware Analysis
- Analyze binary files to extract useful metadata and signatures.
- Perform string extraction, entropy analysis, and PE header enumeration.
- Detect programming languages and packed or obfuscated code.
- Scan binaries using YARA rules for malware signature detection.

# Dependencies
Both sub-projects require Python and certain external tools and libraries. Below are the key dependencies for each:

## Forensic Analysis Dependencies
- Python 3.x
- Libraries: `scapy`, `requests`
- Tools:
  - `tshark` 
  - API keys for VirusTotal and IPinfo (required for specific scripts)

## Malware Analysis Dependencies
- Python 3.x
- Libraries: `yara-python`, `pefile`
- Tools:
  - `strings` (from binutils for string extraction)
  - `yara` (for YARA rule scanning)

# Installation
To set up the environment for both sub-projects, clone the repository and install the necessary dependencies:

```
pip install -r forensic/requirements.txt
pip install -r reverse-malware/requirements.txt
```
Ensure that the necessary external tools (like tshark, strings, and yara) are installed and available in your system's PATH.

# Setting API Keys
Some scripts in the Forensic project require API keys for external services. Add them to your environment variables as follows:

- **Windows** (PowerShell):
```
$env:VIRUSTOTAL_API_KEY="your_api_key"
$env:IPINFO_ACCESS_TOKEN="your_api_key"
```
- **Linux & macOS**:
```
export VIRUSTOTAL_API_KEY=your_api_key
export IPINFO_ACCESS_TOKEN=your_api_key
```

For further information about the usage of the submodules, read their respective README files.
