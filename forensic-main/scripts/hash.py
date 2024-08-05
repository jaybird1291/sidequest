import sys
import subprocess
import os
import hashlib
import json
from collections import defaultdict

CACHE_FILE = 'cache.json'

def load_cache():
    """Load the cache from a file if it exists."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_cache(cache):
    """Save the cache to a file."""
    with open(CACHE_FILE, 'w') as file:
        json.dump(cache, file, indent=4)

def calculate_hash(file_path):
    """Calculate the SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def ensure_tshark_installed():
    """Check if tshark is installed."""
    try:
        subprocess.run(['tshark', '-v'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print("Error: tshark is not installed or not found in PATH.")
        sys.exit(1)

def extract_files(pcap_file, output_dir):
    """Extract files from a PCAP file using tshark."""
    ensure_tshark_installed()
    os.makedirs(output_dir, exist_ok=True)
    protocols = ['http', 'imf', 'smb', 'tftp', 'ftp-data']
    for protocol in protocols:
        subprocess.run([
            'tshark',
            '-r', pcap_file,
            '--export-objects', f'{protocol},{output_dir}'
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rename_files_to_bin(output_dir)

def rename_files_to_bin(output_dir):
    """Rename all extracted files to have a .bin extension."""
    for filename in os.listdir(output_dir):
        file_path = os.path.join(output_dir, filename)
        if os.path.isfile(file_path):
            new_file_path = os.path.splitext(file_path)[0] + '.bin'
            os.rename(file_path, new_file_path)

def analyze_files(output_dir):
    """Analyze extracted files and categorize them by protocol."""
    files_by_protocol = defaultdict(list)
    protocols = ['http', 'imf', 'smb', 'tftp', 'ftp-data']

    for filename in os.listdir(output_dir):
        file_path = os.path.join(output_dir, filename)
        if os.path.isfile(file_path):
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)  # Size in MB
            sha256_hash = calculate_hash(file_path)
            protocol = next((p for p in protocols if p in filename.lower()), 'unknown')
            files_by_protocol[protocol].append((filename, file_size_mb, sha256_hash))

    if not files_by_protocol:
        print("No files were identified in the PCAP.")
        return None

    for protocol in files_by_protocol:
        files_by_protocol[protocol].sort(key=lambda x: x[1], reverse=True)

    return files_by_protocol

def update_output(files_by_protocol):
    """Update the output file with the analyzed results."""
    lines = [
        "=" * 140,
        "Files sorted by protocols:",
        "=" * 140,
        f"{'Protocol':<10} {'Filename':<30} {'Size (MB)':>10} {'SHA256 Hash':^64}",
        "-" * 140
    ]

    for protocol, files in files_by_protocol.items():
        lines.append(f"{protocol.upper()}")
        lines.append("-" * 140)
        for filename, file_size, sha256_hash in files:
            lines.append(f"{'':<10} {filename:<30} {file_size:>10.2f} {sha256_hash:^64}")
        lines.append("-" * 140)

    with open("extracted-hashes.txt", "a") as file:
        file.write("\n".join(lines))

    print("=" * 80)
    print("Extracted Hashes:")
    print("=" * 80)
    print("Results have been saved to 'extracted-hashes.txt'.")

def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: script.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) == 3 else "extracted_files"

    cache = load_cache()
    pcap_hash = calculate_hash(pcap_file)

    if pcap_hash in cache:
        print("=" * 80)
        print("Extracted Hashes:")
        print("=" * 80)
        print("PCAP file already processed. Skipping extraction and analysis.")
    else:
        extract_files(pcap_file, output_dir)
        files_by_protocol = analyze_files(output_dir)

        if files_by_protocol:
            update_output(files_by_protocol)
            cache[pcap_hash] = files_by_protocol
            save_cache(cache)
        else:
            print("=" * 80)
            print("Extracted Hashes:")
            print("=" * 80)
            print("No new files were extracted from the PCAP.")

if __name__ == "__main__":
    main()
