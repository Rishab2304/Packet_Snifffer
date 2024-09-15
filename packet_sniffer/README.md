# Packet Sniffer

## Overview

The Packet Sniffer is a command-line tool designed to capture network packets from a specified network interface. It provides functionalities to filter packets based on IP addresses, port numbers, and protocols, and allows saving the captured packets to a `.pcap` file. This tool is particularly useful for network analysis, troubleshooting, and security assessments.

## Features

- **Customizable Interface**: Select the network interface to sniff packets from.
- **Packet Filtering**: Apply filters based on source/destination IP addresses, port numbers, and protocols.
- **Promiscuous Mode**: Enable promiscuous mode to capture all packets on the network segment.
- **Packet Saving**: Save captured packets to a `.pcap` file for further analysis.
- **Graceful Exit**: Handle interruptions gracefully with `Ctrl+C`.

## usage

sudo python3 sniffer.py [arguments]

## Command-Line Argument

--interface (-i): Network Interface - The network interface to capture packets from. Default is eth0.
--timeout (-t): Sniffing Timeout - The duration to sniff packets in seconds. Set to 0 for unlimited time. Default is 30.
--filter (-f): Custom Filter - A custom BPF (Berkeley Packet Filter) expression to filter packets. Default is None.
--promisc (-p): Promiscuous Mode - Enable promiscuous mode to capture all packets on the network segment.
--pcap (-pcap): PCAP File - File name to save captured packets. If omitted, packets will not be saved.
--src_ip (-src_ip): Source IP - Filter packets based on source IP address.
--dst_ip (-dst_ip): Destination IP - Filter packets based on destination IP address.
--src_port (-src_port): Source Port - Filter packets based on source port number.
--dst_port (-dst_port): Destination Port - Filter packets based on destination port number.
--protocol (-protocol): Protocol - Filter packets based on the protocol (e.g., tcp, udp, icmp)

## Example

Basic Sniffing: Capture packets from the eth0 interface for 60 seconds.

sudo python3 sniffer.py --interface eth0 --timeout 60


Filtering by IP Address: Capture packets from the eth0 interface where the source IP is 192.168.1.1.

sudo python3 sniffer.py --interface eth0 --src_ip 192.168.1.1


Saving to PCAP File: Capture packets from the eth0 interface and save them to capture.pcap.

sudo python3 sniffer.py --interface eth0 --pcap capture.pcap


Using Promiscuous Mode: Capture all packets on the network segment from the eth0 interface and save to capture.pcap.

sudo python3 sniffer.py --interface eth0 --promisc --pcap capture.pcap


Custom Filter Expression: Capture packets with a specific filter expression and save to capture.pcap.

sudo python3 sniffer.py --interface eth0 --filter "tcp and port 80" --pcap capture.pcap

## Installation

Ensure you have Python 3 installed on your system. Install the necessary Python libraries using `pip`:


```bash
pip install scapy
