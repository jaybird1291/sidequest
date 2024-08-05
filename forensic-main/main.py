import subprocess
import sys
import os
import argparse

def run_script(script_name, pcap_file, top_n=None):
    """Execute a Python script with a PCAP file argument and optional top_n argument."""
    script_path = os.path.join(os.path.dirname(__file__), "scripts", script_name)
    command = ["python", script_path, pcap_file]
    if top_n is not None and script_name == "ip.py":
        command.extend(["-z", str(top_n)])
    subprocess.run(command, check=True)

def main():
    parser = argparse.ArgumentParser(description="Run analysis scripts on a PCAP file.")
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    parser.add_argument("-z", "--top", type=int, help="Number of top IPs to display (for ip.py script)")
    
    args = parser.parse_args()

    # List of scripts to execute
    scripts = ["ip.py", "protocol.py", "hash.py", "vt.py"]

    # Execute each script with the PCAP file as an argument
    for script in scripts:
        run_script(script, args.pcap_file, args.top)

if __name__ == "__main__":
    main()