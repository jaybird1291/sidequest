This repository contains a set of scripts for analyzing PCAP files, extracting useful informations and detecting certain characteristics. These tools leverage various libraries and utilities to provide functionalities such as hashing files, extracting files from PCAPs, analyzing protocols, IP addresses, and searching for signatures on VirusTotal.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [Analyze IPs](#analyze-ips)
- [Analyze Protocols](#analyze-protocols)
- [Calculate Hashes](#calculate-hashes)
- [Analyze VirusTotal](#analyze-virustotal)
- [Contributing](#contributing)
- [License](#license)

## Installation 
To use these tools, you need to have Python installed along with the required dependencies. Install the dependencies using the following command:

```sh
pip install -r requirements.txt
```
Make sure you have the following tools installed and accessible in your system's PATH:
- tshark (for packet analysis)
- scapy (for processing PCAP files)
- requests (for HTTP requests)

To use the VirusTotal and IPinfo APIs, you need to set the appropriate API keys in your environment variables. The scripts will look for these keys in your system's environment variables:

- On Windows (PowerShell)
```powershell
$env:VIRUSTOTAL_API_KEY="your_api_key_here"
$env:IPINFO_ACCESS_TOKEN="your_api_key_here"
```

- On Linux/macOS
```sh
export VIRUSTOTAL_API_KEY=your_api_key_here
export IPINFO_ACCESS_TOKEN=your_api_key_here
```

To make these environment variables available in all future shell sessions, you can add them to your shell's configuration file and then reload it (``~/.bashrc`` or ``~/.zshrc`` and then reload it by ``source ~/.bashrc`` or ``source ~/.zshrc``)


## Usage

### Global Usage 
Use main.py to call all sub-scripts:
```sh
python main.py <pcap_file> -z [x]
```
<pcap_file>: Path to the PCAP file to analyze.
[x] (optional): Number of IPs to display by ip.py script (default: 10).

### Analyze IPs - ip.py
Analyzes a PCAP file and displays statistics on IP addresses, including the number of packets sent and received, as well as detailed information on each IP.

```sh
python scripts/ip.py <pcap_file> -z [x]
```
<pcap_file>: Path to the PCAP file to analyze.
[x] (optional): Number of IPs to display by ip.py script (default: 10).

### Analyze Protocols - protocol.py
Analyzes a PCAP file to display statistics on the protocols used, including the total number of packets and data transferred.

```sh
python scripts/protocol.py <pcap_file> 
```
<pcap_file>: Path to the PCAP file to analyze.

### Calculate Hashes - hash.py
Extracts files from a PCAP and calculates SHA256 hashes for each file. Results of hashes are saved to the text file "extracted-hashes.txt" and extracted files in the directory "extracted_files".
```sh
python scripts/hash.py <pcap_file> 
```
<pcap_file>: Path to the PCAP file to analyze.

### Analyze VirusTotal - vt.py
Uploads file hashes to VirusTotal for status checks. Results are saved to the text file "vt_results.txt".
```sh
python scripts/hash.py <pcap_file> 
```
<pcap_file>: Path to the PCAP file to analyze.

This script loads file hashes from extracted-hashes.txt and queries VirusTotal for information on these files.

## Contributing
Contributions are welcome! Please submit pull requests with clear descriptions of the changes. Be sure to add tests for new features and update documentation as necessary.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.