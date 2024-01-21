import argparse
import os
import subprocess
import signal
import sys
import time
from scapy.all import rdpcap, ICMP

"""
@k4n1n
"""


def _arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--read', help='Path to the pcap file to read. If not provided, starts capturing packets.', default=None)
    parser.add_argument('-o', '--output', help='Path to the output file.', default='output.txt')
    return parser.parse_args()

def extract_icmp_payloads(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"File {pcap_file} not found.")
        sys.exit(1)
    payloads = [bytes(packet[ICMP].payload) for packet in packets if packet.haslayer(ICMP)]
    return payloads

def _verify(file_path):
    pcap_magic_numbers = [b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1']
    _, file_extension = os.path.splitext(file_path)
    if file_extension.lower() not in ['.pcap', '.pcapng']:
        return False
    try:
        with open(file_path, 'rb') as f:
            return f.read(4) in pcap_magic_numbers
    except IOError:
        return False

def start_tcpdump(interface='eth0', output_file='d.pcap', filter='icmp'):
    print(f"Starting tcpdump on {interface}, saving to {output_file}.")
    return subprocess.Popen(['sudo', 'tcpdump', '-i', interface, '-w', output_file, filter], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def main():
    args = _arguments()

    if args.read:
        pcap_file = args.read
        if not _verify(pcap_file):
            print("[!] The specified file is not a valid pcap file.")
            sys.exit(1)
    else:
        pcap_file = 'd.pcap'
        tcpdump_proc = start_tcpdump(output_file=pcap_file)
        print("Press Ctrl+C to stop packet capture.")
        try:
            tcpdump_proc.wait()
        except KeyboardInterrupt:
            stop_tcpdump(tcpdump_proc)
    
    payloads = extract_icmp_payloads(pcap_file)
    seen_payloads = set()

    with open(args.output, 'w') as f:
        for payload in payloads:
            try:
                decoded_payload = payload.decode('ascii').strip()
                if decoded_payload not in seen_payloads:
                    seen_payloads.add(decoded_payload)
                    f.write(decoded_payload + '\n')
                    print(decoded_payload)
            except UnicodeDecodeError:
                continue

def stop_tcpdump(tcpdump_proc):
    print("Stopping tcpdump.")
    tcpdump_proc.terminate()
    try:
        tcpdump_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        tcpdump_proc.kill()
    print("tcpdump stopped.")

if __name__ == '__main__':
    main()