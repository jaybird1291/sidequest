import sys
import subprocess
from collections import defaultdict

def analyze_pcap(file_path):
    protocol_stats = defaultdict(lambda: {'packet_count': 0, 'data_transferred': 0, 'client_to_server_bytes': 0, 'server_to_client_bytes': 0})

    # Ensure tshark is installed
    try:
        subprocess.run(['tshark', '-v'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print("Error: tshark is not installed or not found in PATH.")
        sys.exit(1)

    # Run tshark to get the protocol, length, source IP, destination IP, source port, and destination port of each packet
    tshark_cmd = [
        'tshark',
        '-r', file_path,
        '-T', 'fields',
        '-e', '_ws.col.Protocol',
        '-e', 'frame.len',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'tcp.srcport',
        '-e', 'tcp.dstport'
    ]
    
    process = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        print(f"Error running tshark: {stderr.decode().strip()}")
        sys.exit(1)

    total_packets = 0

    for line in stdout.decode().splitlines():
        if not line:
            continue
        fields = line.split('\t')
        if len(fields) != 6:
            continue
        protocol, length, src_ip, dst_ip, src_port, dst_port = fields
        length = int(length)
        protocol_stats[protocol]['packet_count'] += 1
        protocol_stats[protocol]['data_transferred'] += length
        total_packets += 1

        # Determine direction (client to server or server to client)
        # This is a simple heuristic: assume lower port numbers are servers
        if src_port and dst_port:
            if int(src_port) > int(dst_port):
                protocol_stats[protocol]['client_to_server_bytes'] += length
            else:
                protocol_stats[protocol]['server_to_client_bytes'] += length

    sorted_by_packet_count = sorted(protocol_stats.items(), key=lambda x: x[1]['packet_count'], reverse=True)
    sorted_by_data_transferred = sorted(protocol_stats.items(), key=lambda x: x[1]['data_transferred'], reverse=True)

    separator_length = 80

    print("\n" + "="*separator_length)
    print("Protocols sorted by packet count:")
    print("="*separator_length)
    print(f"{'Protocol':<20} {'Total Packets':>15} {'Total %':>10}")
    print("-"*separator_length)
    for protocol, stats in sorted_by_packet_count:
        percentage = (stats['packet_count'] / total_packets) * 100
        print(f"{protocol:<20} {stats['packet_count']:>15} {percentage:>10.2f}%")

    print("\n" + "="*separator_length)
    print("Protocols sorted by data transferred:")
    print("="*separator_length)
    print(f"{'Protocol':<20} {'Total MB':>12} {'Client->Server MB':>18} {'Server->Client MB':>18}")
    print("-"*separator_length)
    for protocol, stats in sorted_by_data_transferred:
        total_mb = stats['data_transferred'] / (1024 * 1024)
        client_to_server_mb = stats['client_to_server_bytes'] / (1024 * 1024)
        server_to_client_mb = stats['server_to_client_bytes'] / (1024 * 1024)
        print(f"{protocol:<20} {total_mb:>12.2f} {client_to_server_mb:>18.2f} {server_to_client_mb:>18.2f}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: script.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_file_path = sys.argv[1]
    analyze_pcap(pcap_file_path)
