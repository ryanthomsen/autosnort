#!/usr/bin/env python3

### IMPORT STATEMENTS ###
import sys
import os
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import *

import getopt

#MAGIC NUMBERS
SID_START = 1000000

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


    if tcpdestport == 80:
      if singlepacket.haslayer(HTTPRequest):  # Checks if packet has payload
        #rawload = singlepacket[0][0][Raw].load
        print("HTTP Request Type: " + str(singlepacket[HTTPRequest].Method))


  if DNS in singlepacket:
    hostname = singlepacket[DNSQR].qname
    print("DNS HostName: " + str(hostname))

  if DNSRR in singlepacket:
    hostaddr = singlepacket[DNSRR].rdata
    #recordtype = singlepacket[DNSRR].qtype
    print("DNS Host Address: " + str(hostaddr)) #+ " | TCP Dest Port: " + str(recordtype))
  
  if UDP in singlepacket:
    udpsrcport = singlepacket[UDP].sport
    udpdestport = singlepacket[UDP].dport
    print("UDP Source Port: " + str(udpsrcport) + " | UDP Dest Port: " + str(udpdestport))
    
  if ICMP in singlepacket:
    icmptype = singlepacket[ICMP].type
    print("ICMP Type: " + str(icmptype))


def RuleMaker(singlepacket) -> list:
  suggestion = ""
  rule_list = []
  if TCP in singlepacket:
    tcpsourceport = singlepacket[TCP].sport
    tcpdestport = singlepacket[TCP].dport
    if tcpsourceport == 1337:
      suggestion += "drop TCP " + \
          singlepacket[IP].src + \
          ' 1337 -> any any (msg: "Suspicious activity on Port 1337"; sid ' + \
          str(SID_START + 1) + ")\n"
      rule_list.append(suggestion)
    if tcpdestport == 1337:
      suggestion += "drop TCP any any -> " + \
          singlepacket[IP].src + \
          ' 1337 (msg: "Suspicious Port activity on 1337"; sid ' + \
          str(SID_START + 2) + ")\n"
      rule_list.append(suggestion)
  #Return the rules
  return rule_list

def HelperMethods(pcap):
  counter = 0
  snort_rules = []
  occurences = []
  for data in pcap:
    rule_list = []
    print(str(counter) + " : ")
    readP(data)
    rule_list = RuleMaker(data)
    for rule in rule_list:
      if rule not in snort_rules:
        snort_rules.append(rule)
        occurences.append(1)
      elif rule in snort_rules:
        occurences[(snort_rules.index(rule))] += 1

    counter +=1
    print("\n\n")
  print("Snort Rule Suggestions: ")
  for index in range(0, len(snort_rules), 1):
    print(snort_rules[index])
    print("# of Packets Flagged: " + str(occurences[index]))
    print("______________________________________________")
  

### MAIN FUNCTION ###
def main():
  #file_name = sys.argv[1]
  file_name = "1337 nc.pcap"
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
