#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

from numpy import array
from numpy import array_split
from pbkdf2 import *
from binascii import a2b_hex, b2a_hex
from scapy.all import *
__author__ = "Abraham Rubinstein et Yann Lederrey"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

#from pbkdf2 import pbkdf2_hex
import hmac
import hashlib


def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen*8+159)/160):
        hmacsha1 = hmac.new(key, A+str.encode(chr(0x00)) +
                            B+str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R+hmacsha1.digest()
    return R[:blen]


def getSSIDFromPcap(pcap_data):
    """
    This function retrieves the SSID from the wpa_handshake.cap capture
    """
    beacon = pcap_data[0]  # beacon is in the first packet
    return beacon[3].info.decode("utf-8") # SSID is in the 802.11 Wireless Management layer

def getAPMacFromPcap(pcap_data):
    """
    This function retrieves the AP MAC from the wpa_handshake.cap capture
    """
    beacon = pcap_data[0]  # beacon is in the first capture's packet
    return beacon[1].addr3.replace(':', '') # source address is in the 802.11 Beacon layer

def getClientMacFromPcap(pcap_data):
    """
    This function retrieves the Client MAC from the wpa_handshake.cap capture
    """
    auth1 = pcap_data[1]  # auth request is in the second capture's packet
    return auth1[0].addr1.replace(':', '') # receiver address is in the 802.11 Authentication layer

def getAuthenticatorNonceFromPcap(pcap_data):
    """
    This function retrieves the Authenticator Nonce from the wpa_handshake.cap capture
    """
    handshake1 = pcap_data[5]  # 4-way handshake first packet is in the sixth capture's packet
    return handshake1[4].load[13:45].hex() # ANonce start at the 13th byte of the eapol payload and it's length is 32 bytes

def getSupplicantNonceFromPcap(pcap_data):
    """
    This function retrieves the Supplicant Nonce from the wpa_handshake.cap capture
    """
    handshake2 = pcap_data[6]  # 4-way handshake second packet is in the seventh capture's packet
    return handshake2[4].info[18:50].hex() # SNonce start at the 18th byte of the eapol payload and it's length is 32 bytes

def getMICFromPcap(pcap_data):
    """
    This function retrieves the MIC from the wpa_handshake.cap capture
    """
    handshake4 = pcap_data[8]  # 4-way handshake last packet is in the ninth capture's packet
    return handshake4[4].info[82:98].hex() # MIC start at the 82th byte of the eapol payload and it's length is 16 bytes

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa = rdpcap("wpa_handshake.cap")

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase = "actuelle"
A = "Pairwise key expansion"  # this string is used in the pseudo-random function

ssid = getSSIDFromPcap(wpa) 
APmac = a2b_hex(getAPMacFromPcap(wpa))
Clientmac = a2b_hex(getClientMacFromPcap(wpa))

# Authenticator and Supplicant Nonces
ANonce = a2b_hex(getAuthenticatorNonceFromPcap(wpa))
SNonce = a2b_hex(getSupplicantNonceFromPcap(wpa))

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = getMICFromPcap(wpa)

B = min(APmac, Clientmac)+max(APmac, Clientmac)+min(ANonce, SNonce) + \
    max(ANonce, SNonce)  # used in pseudo-random function

# cf "Quelques détails importants" dans la donnée
data = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

print("\n\nValues used to derivate keys")
print("============================")
print("Passphrase: ", passPhrase, "\n")
print("SSID: ", ssid, "\n")
print("AP Mac: ", b2a_hex(APmac), "\n")
print("CLient Mac: ", b2a_hex(Clientmac), "\n")
print("AP Nonce: ", b2a_hex(ANonce), "\n")
print("Client Nonce: ", b2a_hex(SNonce), "\n")

# calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)
ssid = str.encode(ssid)
pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

# expand pmk to obtain PTK
ptk = customPRF512(pmk, str.encode(A), B)

# calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16], data, hashlib.sha1)


print("\nResults of the key expansion")
print("=============================")
print("PMK:\t\t", pmk.hex(), "\n")
print("PTK:\t\t", ptk.hex(), "\n")
print("KCK:\t\t", ptk[0:16].hex(), "\n")
print("KEK:\t\t", ptk[16:32].hex(), "\n")
print("TK:\t\t", ptk[32:48].hex(), "\n")
print("MICK:\t\t", ptk[48:64].hex(), "\n")
print("MIC:\t\t", mic.hexdigest(), "\n")
