from scapy.all import *
from scapy.layers.l2 import Ether

def packet_sniffer(interface="eth0", timeout=None, filter_expr=None, promisc=False, pcap_file=None):
    packets = []  # List to store captured packets

    try:
        # Create a raw socket for sniffing
        if promisc:
            print(f"Enabling promiscuous mode on {interface}")
            sniff(iface=interface, filter=filter_expr, timeout=timeout, prn=lambda x: (x.summary(), packets.append(x)), promisc=True)
        else:
            sniff(iface=interface, filter=filter_expr, timeout=timeout, prn=lambda x: (x.summary(), packets.append(x)))

    except KeyboardInterrupt:
        print("\nPacket sniffing interrupted. Exiting...")

    if pcap_file:
        # Save captured packets to a pcap file if a filename is provided
        wrpcap(pcap_file, packets)
        print(f"\nCaptured packets saved to {pcap_file}")

    print(f"\nPacket capture completed on interface {interface}")
