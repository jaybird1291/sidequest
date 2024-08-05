import os
import requests
import json
import time
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored

# Retrieve the API key from the environment variable
API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
if not API_KEY:
    raise ValueError("VIRUSTOTAL_API_KEY environment variable is not set")

VT_API_URL = "https://www.virustotal.com/api/v3/"
EXTRACTED_FILES_DIR = "extracted_files"
HASHES_FILE = "extracted-hashes.txt"
RESULTS_FILE = "vt_results.txt"

def load_hashes():
    hashes = {}
    with open(HASHES_FILE, 'r') as f:
        for line in f:
            if line.startswith("           "):
                parts = line.strip().split()
                if len(parts) == 3:
                    filename, _, hash_value = parts
                    hashes[hash_value] = filename
    return hashes

def scan_hash(session, hash_item):
    hash_value, filename = hash_item
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    response = session.get(f"{VT_API_URL}files/{hash_value}", headers=headers, timeout=(3.05, 27))
    return {'filename': filename, 'hash': hash_value, 'data': response.json().get('data')}

def write_results(results):
    with open(RESULTS_FILE, 'w') as f:
        f.write("KNOWN HASHES:\n")
        for result in results:
            if result['data']:
                last_analysis_stats = result['data']['attributes'].get('last_analysis_stats', {})
                malicious_count = last_analysis_stats.get('malicious', 0)
                total_count = sum(last_analysis_stats.values())
                f.write(f"Filename: {result['filename']}\n")
                f.write(f"Score: {malicious_count}/{total_count}\n")
                f.write(f"VT Link: https://www.virustotal.com/gui/file/{result['hash']}\n")
                f.write(f"Hash: {result['hash']}\n\n")
        
        f.write("UNKNOWN HASHES:\n")
        for result in results:
            if not result['data']:
                f.write(f"Filename: {result['filename']}\n")
                f.write(f"Hash: {result['hash']}\n\n")

def upload_and_analyze_file(session, file_path, filename):
    headers = {"x-apikey": API_KEY}
    
    # Upload file
    with open(file_path, 'rb') as file:
        files = {"file": (filename, file)}
        upload_response = session.post(f"{VT_API_URL}files", headers=headers, files=files)
    
    if upload_response.status_code != 200:
        print(f"Error uploading file {filename}: {upload_response.text}")
        return None

    analysis_id = upload_response.json()['data']['id']
    
    # Wait for analysis to complete
    while True:
        analysis_response = session.get(f"{VT_API_URL}analyses/{analysis_id}", headers=headers)
        if analysis_response.status_code == 200:
            result = analysis_response.json()
            if result['data']['attributes']['status'] == 'completed':
                return result
        time.sleep(20)  # Wait 20 seconds before checking again

def main():
    hashes = load_hashes()
    results = []
    unknown_hashes = []

    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(lambda h: scan_hash(session, h), hashes.items()))

    write_results(results)

    unknown_hashes = [(result['filename'], result['hash']) for result in results if not result['data']]
    print("=" * 80)
    print("VirusTotal:")
    print("=" * 80)
    print(f"Number of unknown hashes: {len(unknown_hashes)}")

    for result in results:
        if result['data']:
            last_analysis_stats = result['data']['attributes'].get('last_analysis_stats', {})
            malicious_count = last_analysis_stats.get('malicious', 0)
            if malicious_count > 0:
                total_count = sum(last_analysis_stats.values())
                score = f"{malicious_count}/{total_count}"
                print(colored(f"Malicious file detected: {result['filename']} (Score: {score})", 'red'))

    if unknown_hashes:
        choice = input("Do you want to scan unknown files? (Y/N): ")
        if choice.lower() == 'y':
            print("Warning: Free API has limitations. Proceeding with scan...")
            for filename, hash_value in unknown_hashes:
                file_path = os.path.join(EXTRACTED_FILES_DIR, filename)
                if os.path.exists(file_path):
                    scan_result = upload_and_analyze_file(session, file_path, filename)
                    if scan_result:
                        attributes = scan_result['data']['attributes']
                        last_analysis_stats = attributes.get('stats', {})
                        malicious_count = last_analysis_stats.get('malicious', 0)
                        total_count = sum(last_analysis_stats.values())
                        with open(RESULTS_FILE, 'a') as f:
                            f.write(f"Newly scanned file:\n")
                            f.write(f"Filename: {filename}\n")
                            f.write(f"Score: {malicious_count}/{total_count}\n")
                            f.write(f"VT Link: https://www.virustotal.com/gui/file/{hash_value}\n")
                            f.write(f"Hash: {hash_value}\n\n")
                        
                        if malicious_count > 0:
                            score = f"{malicious_count}/{total_count}"
                            print(colored(f"Newly scanned malicious file detected: {filename} (Score: {score})", 'red'))
                    
                    time.sleep(15)  # Respect API rate limit

if __name__ == "__main__":
    main()