#!/usr/bin/env python3

### IMPORT STATEMENTS ###
import sys
import os
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR

import getopt

### HELPER FUNCTIONS (IF NECESSARY) ###
def readP(singlepacket):
  # Print IP Layer Rules
	# Check if the IP layer is present in the packet
  if IP in singlepacket:
    ipsource = singlepacket[IP].src
    ipdest = singlepacket[IP].dst
    print("IP Source: " + str(ipsource) + " | IP Dest: " + str(ipdest))

  if TCP in singlepacket:
    tcpsourceport = singlepacket[TCP].sport
    tcpdestport = singlepacket[TCP].dport
    print("TCP Source Port: " + str(tcpsourceport) + " | TCP Dest Port: " + str(tcpdestport))
  
  if DNS in singlepacket:
    hostname = singlepacket[DNSQR].qname
    print("DNS HostName: " + str(hostname))

  if DNSRR in singlepacket:
    hostaddr = singlepacket[DNSRR].rdata
    print("DNS Host Address: " + str(hostaddr))
  
  if UDP in singlepacket:
    udpsrcport = singlepacket[UDP].sport
    udpdestport = singlepacket[UDP].dport
    print("UDP Source Port: " + str(udpsrcport) + " | UDP Dest Port: " + str(udpdestport))
    
  if ICMP in singlepacket:
    icmptype = singlepacket[ICMP].type
    print("ICMP Type: " + str(icmptype))


def HelperMethods(pcap):
  counter = 0
  for data in pcap:
    if counter >= 100:
      print(str(counter) + " : ")
      readP(data)
      counter +=1
      print("\n\n")
  
  

### MAIN FUNCTION ###
def main():
  #file_name = sys.argv[1]
  file_name = "Project test.pcapng"
  # Check if pcap file exists
  # if os.path.isfile(file_name):
  if os.path.isfile(file_name):
    scapy_cap = rdpcap(file_name)
  else:
    print("Error:", file_name, "doesn't not exist.")
    sys.exit(1)
  #open_file = open(file_name)
  HelperMethods(scapy_cap)
  #open_file.close()


### DUNDER CHECK ###
if __name__ == "__main__":
  main()
