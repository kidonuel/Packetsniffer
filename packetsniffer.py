import argparse
from scapy.all import *
from scapy.layers.inet import TCP
from scapy.layers.inet import IP


def http_header(packet):
    http_packet = str(packet)
    if http_packet.find('GET'):
        return 'GET'
    elif http_packet.find('POST'):
        return 'POST'
    else:
        return ''

def packet_callback(packet):
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
        if http_header(packet):
            print('[+] HTTP Request: ' + str(packet[IP].src) + ' -> ' + str(packet[IP].dst) + ' ' + http_header(packet))

parser = argparse.ArgumentParser(description='Python packet sniffer')
parser.add_argument('-i', '--interface', metavar='', required=True, help='Interface to capture packets on')
parser.add_argument('-o', '--output', metavar='', help='File to save captured packets')
args = parser.parse_args()

try:
    if args.output:
        print('[+] Saving packets to file: ' + args.output)
        sniff(iface=args.interface, prn=packet_callback, filter='tcp port 80', store=0, count=0, offline=args.output)
    else:
        sniff(iface=args.interface, prn=packet_callback, filter='tcp port 80', store=0)
except KeyboardInterrupt:
    print('\n[+] User interrupted. Exiting...')
