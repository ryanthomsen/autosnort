#!/usr/bin/env python3

### IMPORT STATEMENTS ###
import sys
import os
#from pigget import *
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

#Filler values

#Read config rules
scan_timing_threshold = 0.1

#Misc vars
packet_list = []
pinged_port_list = {}


### HELPER FUNCTIONS ###

""" def loadP(singlepacket):
  custom_packet = Pigget(singlepacket)
  return custom_packet """

def readP(singlepacket):
  # Print IP source and destination
	# Check if the IP layer is present in the packet
  if IP in singlepacket:
    ipsource = singlepacket[IP].src
    ipdest = singlepacket[IP].dst
    timestamp = singlepacket.time
    print("IP Source: " + str(ipsource) + " | IP Dest: " + str(ipdest))
    if not EPOCH:
      timestamp = int(timestamp)
      timestamp = gmtime(timestamp)
      print("Time: " + str(timestamp[3]).zfill(2) + ":" + str(timestamp[4]).zfill(2) + ":" + str(timestamp[5]).zfill(2) + " GMT, " + str(timestamp[1]) + "/" + str(timestamp[2]) + " /" + str(timestamp[0]))
    elif EPOCH:
      print("Epoch Time: " + str(timestamp))

  # Print TCP source port and destination port
  # Check if TCP is present in the packet
  if TCP in singlepacket:
    tcpsourceport = singlepacket[TCP].sport
    tcpdestport = singlepacket[TCP].dport
    print("TCP Source Port: " + str(tcpsourceport) + " | TCP Dest Port: " + str(tcpdestport))

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
    print("DNS Host Address: " + str(hostaddr)) #+ " | TCP Dest Port: " + str(recordtype))
  
  # Print UDP source port and UDP destination port
  # Check if UDP is present in the packet
  if UDP in singlepacket:
    udpsrcport = singlepacket[UDP].sport
    udpdestport = singlepacket[UDP].dport
    print("UDP Source Port: " + str(udpsrcport) + " | UDP Dest Port: " + str(udpdestport))
  
  # Print ICMP Type:
  # Check if ICMP is present in the packet
  if ICMP in singlepacket:
    icmptype = singlepacket[ICMP].type
    print("ICMP Type: " + str(icmptype))

# Method to suggest snort rules based on packet information
def RuleMaker(singlepacket):
  suggestion = ""
  rule_list = []
  #Scan list dictionary - IP : list containing port-timestamps

  #ICMP Rules

  #TCP Rules
  if TCP in singlepacket:
    tcpsourceport = singlepacket[TCP].sport
    tcpdestport = singlepacket[TCP].dport
    tcpsourceaddr = singlepacket[IP].src
    #tcpdestaddr = singlepacket[IP].dst
    window_size = singlepacket[TCP].window
    str_port_add = ""

    #Checks if suspicious ports
    if tcpsourceport in BAD_PORTS:
      suggestion = "drop TCP " + str(singlepacket[IP].src) + ' ' + str(tcpsourceport) +' -> any any (msg: "Suspicious activity on Port ' + str(tcpsourceport) + '"; sid ' + str(SID_START + 1) + ")\n"
      rule_list.append(suggestion)
    if tcpdestport == BAD_PORTS:
      suggestion = "drop TCP any any -> " + str(singlepacket[IP].src) + ' ' + str(tcpdestport) + ' (msg: "Suspicious Port activity on  ' + str(tcpdestport) + '"; sid ' + str(SID_START + 2) + ")\n"
      rule_list.append(suggestion)
    
    #Checks for a variety of ports being pinged too often (NMAP scan)
    #Adds packet to dictionary
    str_port_add = (str(tcpdestport) + "-" + str(singlepacket[IP].time))
    if tcpsourceaddr in pinged_port_list:
      pinged_port_list[tcpsourceaddr].append(str_port_add)
    else: pinged_port_list[tcpsourceaddr] = [str_port_add]

      #Every 5 packets, checks if 
    #Checks for swapped DHCP ports
    #Checks for unencrypted traffic
    #Checks for failed logins
    #Checks for numerous/frequent requests
      
    #Checks for window sizes
    if window_size > 65535:
      suggestion = ""
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
"""   for packet in pcap:
    packet_list.append(loadP(packet)) """
  
print(packet_list)
  
  

### MAIN FUNCTION ###
def main():
  #file_name = sys.argv[1]
  file_name = "Remote_NMAP.pcap"
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

  #debug dictionary printing
  ppl_keys = list(pinged_port_list)
  ppl_vals = list(pinged_port_list.values())
  ppl_len = len(pinged_port_list)
  debug_counter = 0
  while debug_counter < ppl_len:
    print("\n" + "_____________" + "\n")
    print(str(ppl_keys[debug_counter]) + " : " + str(ppl_vals[debug_counter]))
    debug_counter +=1

  #open_file.close()
    
### DUNDER CHECK ###
if __name__ == "__main__":
  main()
