#!/usr/bin/env python
CIPHER = ("Tr3v0rC2R0x@nd1s@w350m3#TrevorForget")


import random
import base64
import time
import subprocess
import hashlib
from Cryptodome import Random
from Cryptodome.Cipher import AES
import sys
import platform

# AES Support for Python2/3 - http://depado.markdownblog.com/2015-05-11-aes-cipher-with-python-3-x
class AESCipher(object):
    """
    A classical AES Cipher. Can use any size of data and any size of password thanks to padding.
    Also ensure the coherence and the type of the data with a unicode to byte converter.
    """
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
from scapy.all import rdpcap
import re

# Replace 'your_file.pcap' with the path to your pcap file
pcap_file = 'compromised.pcapng'

# Read packets from the pcap file
packets = rdpcap(pcap_file)

# Define a regular expression pattern to match the 'guid' parameter in URLs
guid_pattern = re.compile(r'guid=([^&\s]+)')
old_css=re.compile(r'oldcss=([^&\s]+)')
# Extract 'guid' values from HTTP packets
guid_values = []
old_css_value=[]
for packet in packets:
    if packet.haslayer('Raw') and packet.haslayer('TCP'):
        payload = packet['Raw'].load.decode('utf-8', errors='ignore')
        if 'GET /' in payload and 'Host:' in payload:
            guid_match = guid_pattern.search(payload)
            if guid_match:
                guid_values.append(guid_match.group(1))
        if '!--'in payload:
            oldcss_match=old_css.search(payload)
            if oldcss_match:
                old_css_value.append(oldcss_match.group(1))

import base64
# Print the extracted 'guid' values

for old_value in old_css_value:
    print("-----------------------------")
    print("Server Command")
    cipher = AESCipher(CIPHER)
    encrypted_text = ""
    
    decrypted_text = cipher.decrypt(old_value)
    print(decrypted_text)
for guid_value in guid_values:
    print("-----------------------------")
    print("Client Response")
    cipher2 = AESCipher(CIPHER)
    encrypted_text = ""
    
    decrypted_text = cipher2.decrypt(base64.b64decode(guid_value))
    print(decrypted_text)
