#!/usr/bin/env python3

### IMPORT STATEMENTS ###
import sys
import os
from time import gmtime
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import *
from time import gmtime, localtime


#MAGIC NUMBERS
GM_T = True
#Object to make reading packets easier
class Pigget:
    def __init__(self, singlepacket):
      if IP in singlepacket:
        self.ipsource = singlepacket[IP].src
        self.ipdest = singlepacket[IP].dst
        self.timestamp = singlepacket.time
        if TCP in singlepacket:
            self.tcpsourceport = singlepacket[TCP].sport
            self.tcpdestport = singlepacket[TCP].dport
            self.timestmptcp = singlepacket.time
            if self.tcpdestport == 80:
                if singlepacket.haslayer(HTTPRequest):  # Checks if packet has payload
                    #rawload = singlepacket[0][0][Raw].load
                    self.http_method = singlepacket[HTTPRequest].Method
        if UDP in singlepacket:
            self.udpsrcport = singlepacket[UDP].sport
            self.udpdestport = singlepacket[UDP].dport
        if ICMP in singlepacket:
            self.icmptype = singlepacket[ICMP].type
          # Print DNS Hostname
	    # Check if DNS is present in the packet
        if DNS in singlepacket:
            self.hostname = singlepacket[DNSQR].qname
        if DNSRR in singlepacket:
            self.hostaddr = singlepacket[DNSRR].rdata
            #self.recordtype = singlepacket[DNSRR].qtype

    def __str__(self):
        result = ''
        # Print IP source and destination
        # Check if the IP layer is present in the packet
        if 'self.ipsource' in locals() and 'self.ipdest' in locals():
            result += ("IP Source: " + str(self.ipsource) + " | IP Dest: " + str(self.ipdest) + "\n")
        if 'self.timestamp' in locals():
            if GM_T:
                self.timestamp = gmtime(self.timestamp)
                result += ("Time: " + str(self.timestamp[3]).zfill(2) + ":" + str(self.timestamp[4]).zfill(2) + ":" + str(self.timestamp[5]).zfill(
                    2) + " GMT, " + str(self.timestamp[1]) + "/" + str(self.timestamp[2]) + " /" + str(self.timestamp[0]) + "\n")
            elif not GM_T:
                result += ("Epoch Time: " + str(self.timestamp) + "\n")
        # Print TCP source port and destination port
        # Check if TCP is present in the packet
        if 'self.tcpdestport' in locals() and 'self.tcpsourceport' in locals():
            result += ("TCP Source Port: " + str(self.tcpsourceport) +
                       " | TCP Dest Port: " + str(self.tcpdestport) + "\n")
            # Print HTTP Request Type
            # Check if HTTP is present in the packet
            if 'self.http_method' in locals():  # Checks if packet has payload
                #rawload = singlepacket[0][0][Raw].load
                result += ("HTTP Request Type: " +
                           str(self.http_method) + "\n")
        # Print DNS Hostname
        # Check if DNS is present in the packet
        if 'self.hostname' in locals():
            result += ("DNS HostName: " + str(self.hostname) + "\n")
        # Print DNS Host Address
        # Check if Scapy is able to load additional DNS information
        if 'self.hostaddr' in locals():
            # + " | TCP Dest Port: " + str(self.recordtype))
            result += ("DNS Host Address: " + str(self.hostaddr) + "\n")
        
        # Print UDP source port and UDP destination port
        # Check if UDP is present in the packet
        if 'self.udpdestport' in locals() and 'self.udpsrcport' in locals():
            result += ("UDP Source Port: " + str(self.udpsrcport) +
                       " | UDP Dest Port: " + str(self.udpdestport) + "\n")
        
        # Print ICMP Type:
        # Check if ICMP is present in the packet
        if 'self.icmptype' in locals():
            result += ("ICMP Type: " + str(self.icmptype) + "\n")
        return result
