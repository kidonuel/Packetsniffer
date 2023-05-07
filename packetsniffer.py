import argparse
from scapy.all import *

parser = argparse.ArgumentParser(description='Simple network sniffer')
parser.add_argument('-i', '--interface', help='Network interface to sniff on', required=True)
parser.add_argument('-t', '--timeout', help='Timeout for the sniff function', default=10)
parser.add_argument('-f', '--filter', help='BPF filter for the sniff function', default='tcp port 80')
args = parser.parse_args()

def packet_callback(packet):
    print(packet.summary())

sniff(iface=args.interface, timeout=int(args.timeout), filter=args.filter, prn=packet_callback)
