from scapy.all import rdpcap, IP
from collections import defaultdict
import ipinfo
import argparse
import os

def get_ip_info(ip: str, access_token: str) -> dict:
    """Fetch IP details from IPinfo."""
    handler = ipinfo.getHandler(access_token)
    return handler.getDetails(ip)

def analyze_pcap(pcap_file: str) -> defaultdict:
    """Analyze a PCAP file and count packets sent and received by each IP."""
    packets = rdpcap(pcap_file)
    ip_stats = defaultdict(lambda: {'packets_sent': 0, 'packets_received': 0})

    for packet in packets:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ip_stats[src_ip]['packets_sent'] += 1
            ip_stats[dst_ip]['packets_received'] += 1

    return ip_stats

def print_ip_stats(ip: str, stats: dict, access_token: str) -> None:
    """Print detailed information for a given IP."""
    try:
        details = get_ip_info(ip, access_token)
        print(f"IP: {ip}")
        print("-" * 80)
        print(f"{'Packets Sent:':<30} {stats['packets_sent']}")
        print(f"{'Packets Received:':<30} {stats['packets_received']}")
        print(f"{'City:':<30} {getattr(details, 'city', 'Unknown')}")
        print(f"{'Region:':<30} {getattr(details, 'region', 'Unknown')}")
        print(f"{'Country:':<30} {getattr(details, 'country', 'Unknown')}")
        print(f"{'Location (lat, long):':<30} {getattr(details, 'loc', 'Unknown')}")
        print(f"{'Organization:':<30} {getattr(details, 'org', 'Unknown')}")
        print(f"{'Postal Code:':<30} {getattr(details, 'postal', 'Unknown')}")
        print(f"{'Timezone:':<30} {getattr(details, 'timezone', 'Unknown')}")
        print(f"{'Tor Exit Node:':<30} {'Yes' if 'tor' in getattr(details, 'all', '') else 'No'}")
    except Exception as e:
        print(f"Error retrieving information for IP {ip}: {e}")

def main() -> None:
    """Main function to parse arguments and print IP stats."""
    parser = argparse.ArgumentParser(description="Analyze a PCAP file and get IP statistics.")
    parser.add_argument('pcap_file', type=str, help='Path to the PCAP file')
    parser.add_argument('-z', '--top', type=int, default=10, help='Number of top IPs to display (default: 10)')

    args = parser.parse_args()
    
    # Retrieve the access token from the environment variable
    access_token = os.environ.get("IPINFO_ACCESS_TOKEN")
    if not access_token:
        raise ValueError("IPINFO_ACCESS_TOKEN environment variable is not set")
    
    ip_stats = analyze_pcap(args.pcap_file)
    
    if not ip_stats:
        print("No IP statistics found.")
        return
    
    # Sort IPs by packets sent and received
    sorted_by_sent = sorted(ip_stats.items(), key=lambda item: item[1]['packets_sent'], reverse=True)[:args.top]
    sorted_by_received = sorted(ip_stats.items(), key=lambda item: item[1]['packets_received'], reverse=True)[:args.top]
    
    print("=" * 80)
    print(f"Top {args.top} IPs with most packets sent:")
    print("=" * 80)
    for ip, stats in sorted_by_sent:
        print_ip_stats(ip, stats, access_token)
        print("\n" + "-" * 80)
    
    print("\n" + "=" * 80)
    print(f"Top {args.top} IPs with most packets received:")
    print("=" * 80)
    for ip, stats in sorted_by_received:
        print_ip_stats(ip, stats, access_token)
        print("\n" + "-" * 80)

if __name__ == '__main__':
    main()