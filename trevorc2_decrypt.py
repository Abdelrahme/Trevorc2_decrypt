#!/usr/bin/env python

import argparse
import base64
import hashlib
import re
from Cryptodome import Random
from Cryptodome.Cipher import AES
from scapy.all import rdpcap

# AES Cipher for decryption
class AESCipher(object):
    def __init__(self, key):
        self.bs = 16
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Decrypt TrevorC2 network traffic data")
    parser.add_argument("-i", "--input", required=True, help="Path to the input pcap file")
    return parser.parse_args()

def main():
    # Set cipher key
    CIPHER = "Tr3v0rC2R0x@nd1s@w350m3#TrevorForget"

    # Parse arguments
    args = parse_args()
    pcap_file = args.input

    # Read packets from the pcap file
    packets = rdpcap(pcap_file)

    # Define a regular expression pattern to match 'guid' and 'oldcss' parameters in URLs
    guid_pattern = re.compile(r'guid=([^&\s]+)')
    old_css_pattern = re.compile(r'oldcss=([^&\s]+)')

    # Extract 'guid' and 'oldcss' values from HTTP packets
    guid_values = []
    old_css_values = []
    for packet in packets:
        if packet.haslayer('Raw') and packet.haslayer('TCP'):
            payload = packet['Raw'].load.decode('utf-8', errors='ignore')
            if 'GET /' in payload and 'Host:' in payload:
                guid_match = guid_pattern.search(payload)
                if guid_match:
                    guid_values.append(guid_match.group(1))
            if '!--' in payload:
                oldcss_match = old_css_pattern.search(payload)
                if oldcss_match:
                    old_css_values.append(oldcss_match.group(1))

    # Decrypt and print the extracted values
    cipher = AESCipher(CIPHER)
    
    for old_value in old_css_values:
        print("-----------------------------")
        print("Server Command")
        decrypted_text = cipher.decrypt(old_value)
        print(decrypted_text)

    for guid_value in guid_values:
        print("-----------------------------")
        print("Client Response")
        decrypted_text = cipher.decrypt(base64.b64decode(guid_value))
        print(decrypted_text)

if __name__ == "__main__":
    main()
