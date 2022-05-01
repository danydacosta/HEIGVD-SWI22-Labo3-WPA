#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Descr
"""

from numpy import array
from numpy import array_split
from pbkdf2 import *
from binascii import a2b_hex, b2a_hex
from scapy.all import *
from wpa_key_derivation_p1 import getSSIDFromPcap, getAPMacFromPcap, getClientMacFromPcap, getAuthenticatorNonceFromPcap, getSupplicantNonceFromPcap, customPRF512, getMICFromPcap

__author__ = "Dany Oliveira da Costa & Stefan Simeunovic"
__version__ = "1.0"
__status__ = "Prototype"

#from pbkdf2 import pbkdf2_hex
import hmac
import hashlib

def getWPAVersionFromPcap(pcap_data):
    """
    This function figures out what version of WPA is used based on the KeyDescriptorVersion field from the 1st message of the 4-way handshake from the wpa_handshake.cap capture

    return 0 for WPA or 1 for WPA2
    """
    handshake1 = pcap_data[5]  # 4-way handshake first packet is in the fifth capture's packet
    kdv = int.from_bytes(handshake1[4].load[2:3], 'big') # Key descriptor version start at the 3rd byte of the eapol payload and it's length is 4 bits
    if kdv & 2 == 2: 
        return 1

    return 1 if kdv & 2 == 2 else 0


WORDLIST_FILENAME = 'wordlist.txt_scaircrack.txt'
wpa = rdpcap("wpa_handshake.cap")
A = "Pairwise key expansion"  # this string is used in the pseudo-random function
ssid = getSSIDFromPcap(wpa) 
APmac = a2b_hex(getAPMacFromPcap(wpa))
Clientmac = a2b_hex(getClientMacFromPcap(wpa))
ANonce = a2b_hex(getAuthenticatorNonceFromPcap(wpa))
SNonce = a2b_hex(getSupplicantNonceFromPcap(wpa))
mic_to_test = getMICFromPcap(wpa)

print("\n\nValues used found in the .pcap")
print("============================")
print("SSID: ", ssid, "\n")
print("AP Mac: ", b2a_hex(APmac), "\n")
print("CLient Mac: ", b2a_hex(Clientmac), "\n")
print("AP Nonce: ", b2a_hex(ANonce), "\n")
print("Client Nonce: ", b2a_hex(SNonce), "\n")
print("MIC: ", mic_to_test, "\n")

B = min(APmac, Clientmac)+max(APmac, Clientmac)+min(ANonce, SNonce) + \
    max(ANonce, SNonce)  # used in pseudo-random function

data = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

wordlist = open(WORDLIST_FILENAME, 'r')

print("\n\nResults for the passphrases found in " + WORDLIST_FILENAME)
print("============================")
count = 0
# browse the wordlist file, line by line
for passphrase in wordlist.readlines():
    count += 1
    passphrase = passphrase.strip() # remove the new line char

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    bytespassphrase = str.encode(passphrase)
    bytesssid = str.encode(ssid)
    pmk = pbkdf2(hashlib.sha1, bytespassphrase, bytesssid, 4096, 32)
    ptk = customPRF512(pmk, str.encode(A), B) # expand pmk to obtain PTK

    # use MD5 or SHA-1 depending on the WPA version used
    if getWPAVersionFromPcap(wpa) == 1:
        mic = hmac.new(ptk[0:16], data, hashlib.sha1).hexdigest()[0:32]
    else:
        mic = hmac.new(ptk[0:16], data, hashlib.md5).hexdigest()[0:32]

    result = "CORRECT" if mic == mic_to_test else "INCORRECT"
    
    # let's compare the mic calculated and the mic from the .pcap
    print("Passphrase \"" + passphrase + "\" is : " + result)

