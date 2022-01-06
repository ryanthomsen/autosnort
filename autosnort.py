#!/usr/bin/env python3

### IMPORT STATEMENTS ###
import sys
import os
from pigget import *
from autogui import *
from autorule import *
from time import gmtime
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import *
from time import gmtime, localtime

<<<<<<< Updated upstream
#MAGIC NUMBERS
SID_START = 1000000
BAD_PORTS = [1337, 666, 31, 1170, 1234, 1243, 1981, 2001, 2023, 2140, 2989, 3024, 3150, 3700, 4950, 6346, 6400, 6667, 6670, 12345,
             12346, 16660, 18753, 20034, 20432, 20433, 27374, 27444, 27665, 30100, 31335, 31337, 33270, 33567, 33568, 40421, 60008, 65000]
#Output config rules
include_all_packets = False
include_PKT_numbers = False
EPOCH = False
<<<<<<< Updated upstream
Enable_WhiteList = False

=======
PRINTPACKET = True
>>>>>>> Stashed changes
#Read config rules


packet_list = []


### HELPER FUNCTIONS ###

def loadP(singlepacket, packetnum):
  custom_packet = Pigget(singlepacket, packetnum)
  return custom_packet

<<<<<<< Updated upstream

def readP(singlepacket):
  # Print IP source and destination
	# Check if the IP layer is present in the packet
  if IP in singlepacket:
    ipsource = singlepacket[IP].src
    ipdest = singlepacket[IP].dst
    timestamp = singlepacket.time
    print("IP Source: " + str(ipsource) + " | IP Dest: " + str(ipdest))
    if not EPOCH:
      timestamp = gmtime(timestamp)
<<<<<<< Updated upstream
      print("Time: " + str(timestamp[3]).zfill(2) + ":" + str(timestamp[4]).zfill(2) + ":" + str(timestamp[5]).zfill(2) + " GMT, " + str(timestamp[1]) + "/" + str(timestamp[2]) + " /" + str(timestamp[0]))
=======
      print("Time: " + str(timestamp[3]).zfill(2) + ":" + str(timestamp[4]).zfill(2) + ":" + str(
          timestamp[5]).zfill(2) + " GMT, " + str(timestamp[1]) + "/" + str(timestamp[2]) + " /" + str(timestamp[0]))
>>>>>>> Stashed changes
    elif EPOCH:
      print("Epoch Time: " + str(timestamp))

  # Print TCP source port and destination port
  # Check if TCP is present in the packet
  if TCP in singlepacket:
    tcpsourceport = singlepacket[TCP].sport
    tcpdestport = singlepacket[TCP].dport
    print("TCP Source Port: " + str(tcpsourceport) +
          " | TCP Dest Port: " + str(tcpdestport))

    # Print HTTP Request Type
    # Check if HTTP is present in the packet
    if tcpdestport == 80:
      if singlepacket.haslayer(HTTPRequest):  # Checks if packet has payload
        #rawload = singlepacket[0][0][Raw].load
        print("HTTP Request Type: " + str(singlepacket[HTTPRequest].Method))

  # Print DNS Hostname
	# Check if DNS is present in the packet
  if DNS in singlepacket:
    hostname = singlepacket[DNSQR].qname
    print("DNS HostName: " + str(hostname))

  # Print DNS Host Address
  # Check if Scapy is able to load additional DNS information
  if DNSRR in singlepacket:
    hostaddr = singlepacket[DNSRR].rdata
    #recordtype = singlepacket[DNSRR].qtype
    # + " | TCP Dest Port: " + str(recordtype))
    print("DNS Host Address: " + str(hostaddr))

  # Print UDP source port and UDP destination port
  # Check if UDP is present in the packet
  if UDP in singlepacket:
    udpsrcport = singlepacket[UDP].sport
    udpdestport = singlepacket[UDP].dport
    print("UDP Source Port: " + str(udpsrcport) +
          " | UDP Dest Port: " + str(udpdestport))

  # Print ICMP Type:
  # Check if ICMP is present in the packet
  if ICMP in singlepacket:
    icmptype = singlepacket[ICMP].type
    print("ICMP Type: " + str(icmptype))

=======
>>>>>>> Stashed changes
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

<<<<<<< Updated upstream

def HelperMethods(pcap):
=======
def printList(list):
    for item in list:
      print(item)

def AnalayzePkts(pcap):
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream

    counter += 1
    print("\n\n")
=======
    counter +=1
    packet_list.append(loadP(packet, counter))
  if PRINTPACKET:
    printList(packet_list)

  print("\n\n")
>>>>>>> Stashed changes
  print("Snort Rule Suggestions: ")
  for index in range(0, len(snort_rules), 1):
    print(snort_rules[index])
    print("# of Packets Flagged: " + str(occurences[index]))
    print("______________________________________________")
<<<<<<< Updated upstream
  for packet in pcap:
    packet_list.append(loadP(packet))
<<<<<<< Updated upstream
  
  print(packet_list)
  
=======
  for item in packet_list:
    print(item)
    input()
=======
    
  

>>>>>>> Stashed changes

>>>>>>> Stashed changes

### MAIN FUNCTION ###
def main():
  file_name = sys.argv[1]
  #file_name = "1337 nc.pcap"
  #file_name = "Project test.pcapng"
  # Check if pcap file exists
  if os.path.isfile(file_name):
    scapy_cap = rdpcap(file_name)
  else:
    print("Error:", file_name, "doesn't not exist.")
    sys.exit(1)
<<<<<<< Updated upstream
  #open_file = open(file_name)
  HelperMethods(scapy_cap)
=======
### MAIN FUNCTION ###
def main():
    print(sys.argv[1])
    input()
    read_conf()
    #Open File Option
    if sys.argv[1] == "-o":
      file_name = sys.argv[2]
      if os.path.isfile(file_name):
        scapy_cap = rdpcap(file_name)
      else:
        print("Error:", file_name, "doesn't not exist.")
        sys.exit(1)
      run_pcap(scapy_cap)
    
    #Listen Mode Option
    elif sys.argv[1] == "-l":
      file_name = sys.argv[2]
      num_pack = sys.argv[3]
      pcap1 = listen4pigs(num_pack)
      run_pcap(pcap1)

    if sys.argv[1] == "-p":
      if len(sys.argv) == 3:
        file_name = sys.argv[2]
        if(".txt" == file_name[-4:len(file_name)]):
            f=open(file_name)
            f.readlines()
            f.close()
        else:
            print("Must be a pigget file followed by a packet number / range of packet numbers.")
        num_pack = sys.argv[3]
        if ("-" in num_pack):
          plist = num_pack.split("-")
          while(plist[0] < plist[1]):
            print(plist[0])
            plist[0] = plist[0] + 1

        pcap1 = listen4pigs(num_pack)
        run_pcap(pcap1)

    if sys.argv[1] == "-g":
        load_GUI()

    if sys.argv[1] == "-help":
      file_name = sys.argv[2]
      print("Welcome to Auto Snort!\n"
            "This is a tool for automatically suggesting snort rules.\n"
            "Options available are\n"
            "Open pcap/pigget.txt file for analysis     ./autosnort -o filename\n"
            "Listen for x # of packets then analyze         ./autosnort -l #ofpackets\n"
            "View specific packet(s) info in a pigget.txt file    ./autosnort -p piggetfilename packet(s)num2view\n"
            "Open autosnort GUI     ./autosnort -g\n"
            "Open autosnort help page     ./autosnort -help\n"
            "Script made by Ryan Thomsen and Matt Ages\n"
            "Pigget.txt file is just a text file saved by Autosnort."
            )
    else:
      print("Uknown Arguments given. Try ./autosnort -help")



    #   #file_name = sys.argv[1]
    #   #file_name = "1337 nc.pcap"
    #   file_name = "Project test.pcapng"
    #   # Check if pcap file exists
    #   # if os.path.isfile(file_name):
    #   if os.path.isfile(file_name):
    #     scapy_cap = rdpcap(file_name)
    #   else:
    #     print("Error:", file_name, "doesn't not exist.")
    #     sys.exit(1)
    #   run_pcap(scapy_cap)
>>>>>>> Stashed changes



=======
  AnalayzePkts(scapy_cap)
  print("Press any key to end.")
  input()
    
>>>>>>> Stashed changes
### DUNDER CHECK ###
if __name__ == "__main__":
  main()
