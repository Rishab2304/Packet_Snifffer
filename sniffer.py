import argparse
from capture import packet_sniffer
from filters import create_filter_expression

def main():
    # Argument parser for command line options
    parser = argparse.ArgumentParser(description="A simple packet sniffer with default options.")

    # Define arguments with default values
    parser.add_argument('--interface', type=str, default='eth0', help='Network interface to sniff on (default: eth0)')
    parser.add_argument('--timeout', type=int, default=30, help='Sniffing timeout in seconds (set to 0 for unlimited)')
    parser.add_argument('--filter', type=str, default='', help='Packet filter (default: None)')
    parser.add_argument('--promisc', action='store_true', help='Enable promiscuous mode (default: False)')
    parser.add_argument('--pcap', type=str, help='File name to save captured packets (optional)')
    parser.add_argument('--src_ip', type=str, help='Source IP address to filter on')
    parser.add_argument('--dst_ip', type=str, help='Destination IP address to filter on')
    parser.add_argument('--src_port', type=int, help='Source port number to filter on')
    parser.add_argument('--dst_port', type=int, help='Destination port number to filter on')
    parser.add_argument('--protocol', type=str, help='Protocol to filter on (e.g., tcp, udp, icmp)')

    # Parse the arguments
    args = parser.parse_args()

    # Set timeout to None if user inputs 0 for unlimited timeout
    timeout = None if args.timeout == 0 else args.timeout

    # Create a filter expression based on the provided filtering options
    filter_expr = create_filter_expression(src_ip=args.src_ip, dst_ip=args.dst_ip, src_port=args.src_port, dst_port=args.dst_port, protocol=args.protocol, custom_filter=args.filter)

    # Run the packet sniffer with the parsed arguments
    packet_sniffer(interface=args.interface, timeout=timeout, filter_expr=filter_expr, promisc=args.promisc, pcap_file=args.pcap)

if __name__ == "__main__":
    main()
