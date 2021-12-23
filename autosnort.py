#!/usr/bin/env python3

### IMPORT STATEMENTS ###
import sys
import os
import socket
from pigget import *
from time import gmtime
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import *
from time import gmtime, localtime

#MAGIC NUMBERS
SID_START = 1000000
BAD_PORTS = [1337, 666, 31, 1170, 1234, 1243, 1981, 2001, 2023, 2140, 2989, 3024, 3150, 3700, 4950, 6346, 6400, 6667, 6670, 12345,
             12346, 16660, 18753, 20034, 20432, 20433, 27374, 27444, 27665, 30100, 31335, 31337, 33270, 33567, 33568, 40421, 60008, 65000]
#Output config rules
include_all_packets = False
include_PKT_numbers = False
EPOCH = False
Enable_WhiteList = False
PRINTPCKT = True

#Read config rules


packet_list = []


### HELPER FUNCTIONS ###

def loadP(singlepacket, counter):
  custom_packet = Pigget(singlepacket, counter)
  return custom_packet

def printlist(list):
  for item in list:
    print(item)

# Method to suggest snort rules based on packet information
def RuleMaker(singlepacket) -> list:
  suggestion = ""
  rule_list = []

  #TCP Rules
  if TCP in singlepacket:
    tcpsourceport = singlepacket[TCP].sport
    tcpdestport = singlepacket[TCP].dport

    #Checks if suspicious ports
    if tcpsourceport in BAD_PORTS:
      suggestion = "drop TCP " + str(singlepacket[IP].src) + ' ' + str(
          tcpsourceport) + ' -> any any (msg: "Suspicious activity on Port ' + str(tcpsourceport) + '"; sid ' + str(SID_START + 1) + ")\n"
      rule_list.append(suggestion)
    if tcpdestport == BAD_PORTS:
      suggestion = "drop TCP any any -> " + str(singlepacket[IP].src) + ' ' + str(
          tcpdestport) + ' (msg: "Suspicious Port activity on  ' + str(tcpdestport) + '"; sid ' + str(SID_START + 2) + ")\n"
      rule_list.append(suggestion)
  #Return the rules
  return rule_list


def HelperMethods(pcap):
  counter = 0
  snort_rules = []
  occurences = []
  for packet in pcap:
    rule_list = []
    rule_list = RuleMaker(packet)
    for rule in rule_list:
      if rule not in snort_rules:
        snort_rules.append(rule)
        occurences.append(1)
      elif rule in snort_rules:
        occurences[(snort_rules.index(rule))] += 1
    counter += 1
    packet_list.append(loadP(packet, counter))
  if(PRINTPCKT):
    printlist(packet_list)
  print("\n\n")
  print("Snort Rule Suggestions: ")
  for index in range(0, len(snort_rules), 1):
    print(snort_rules[index])
    print("# of Packets Flagged: " + str(occurences[index]))
    print("______________________________________________")


### MAIN FUNCTION ###
def main():
  file_name = sys.argv[1]
  #file_name = "1337 nc.pcap"
  #file_name = "Project test.pcapng"
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
