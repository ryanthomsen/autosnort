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
private_port_ranges = ["1025-65535"]
whitelisted_ip_addresses = []
nmap_unique_ports = 15
nmap_percentage_of_violations = 0.75

#Misc vars
packet_list = []
pinged_port_list = {}

### HELPER FUNCTIONS ###

def port_range_check(port_num) -> int:
  counter = 0
  while counter < len(private_port_ranges):
    min_val = 0
    max_val = 0
    delim = 0
    entry_str = private_port_ranges[counter]
    #checks if the entry is a range, or single int
    if "-" in entry_str:
      delim = entry_str.index("-")
      min_val = int(entry_str[:delim])
      max_val = int(entry_str[delim+1:])
      #checks if the port is in the range
      if port_num in range(min_val, max_val):
        return False
      else:
        counter += 1
    else:
      if port_num == int(entry_str):
        return False
      else: counter += 1
  return True

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
    tcpdestaddr = singlepacket[IP].dst
    window_size = singlepacket[TCP].window
    str_port_add = ""
    delim01 = 0

    #Checks if suspicious ports
    if tcpsourceport in BAD_PORTS:
      suggestion = "drop TCP " + str(singlepacket[IP].src) + ' ' + str(tcpsourceport) +' -> any any (msg: "Suspicious activity on Port ' + str(tcpsourceport) + '"; sid ' + str(SID_START + 1) + ")\n"
      rule_list.append(suggestion)
    if tcpdestport == BAD_PORTS:
      suggestion = "drop TCP any any -> " + str(singlepacket[IP].src) + ' ' + str(tcpdestport) + ' (msg: "Suspicious Port activity on  ' + str(tcpdestport) + '"; sid ' + str(SID_START + 2) + ")\n"
      rule_list.append(suggestion)
    
    #Checks for a variety of ports being pinged too often (NMAP scan)
    #Adds packet to dictionary
    if port_range_check(tcpdestport):
      source_dest_pair = tcpsourceaddr + ":" + tcpdestaddr
      str_port_add = (str(tcpdestport) + "-" + str(singlepacket.time))
      if source_dest_pair in pinged_port_list:
        pinged_port_list[source_dest_pair].append(str_port_add)
      else: pinged_port_list[source_dest_pair] = [str_port_add]
    
    #Checks for swapped DHCP ports
    #Checks for unencrypted traffic
    #Checks for failed logins
    #Checks for numerous/frequent requests
      
    #Checks for window sizes
    if window_size > 65535:
      suggestion = ""
      rule_list.append(suggestion)

  #UDP rules
  #Bulk NMAP info for UDP ports
  if UDP in singlepacket:
    udpdestport = singlepacket[UDP].dport
    udpsourceaddr = singlepacket[IP].src
    udpdestaddr = singlepacket[IP].dst


    if port_range_check(udpdestport):
      source_dest_pair = udpsourceaddr + ":" + udpdestaddr
      str_port_add = (str(udpdestport) + "-" + str(singlepacket.time))
      if source_dest_pair in pinged_port_list:
        pinged_port_list[source_dest_pair].append(str_port_add)
      else: pinged_port_list[source_dest_pair] = [str_port_add]

  #Return the rules
  return rule_list

def substr_in_list(substr,inlist):
  #takes in a list and a substring, and returns a l8st of occurances
  #only if substring is at the beginning of the string
  new_list = []
  counter01 = 0
  fullstr = ""
  while counter01 < len(inlist):
    fullstr = inlist[counter01]
    if isinstance(inlist[counter01], str):
      if substr in inlist[counter01] and inlist[counter01].index(substr) == 0:
        new_list.append(fullstr)
    counter01 += 1
  return new_list

def nmap_scan_check(PPL_list):
  counter01 = 0
  key_list = list(PPL_list)
  val_list = list(PPL_list.values())
  #print("\n" + str(val_list) + "___________\n")
  #goes through list of IPs
  while counter01 < len(key_list):
    counter02 = 0
    #If a port shows up more than twice, we remove all but the first and last occurances
    #Goes through the list of ports
    new_val_list = val_list[counter01]
    while counter02 < len(val_list[counter01]):
      current_port_string = val_list[counter01][counter02]
      prt_str_delim = current_port_string.index("-")
      this_port = current_port_string[:prt_str_delim+1]
      #takes the prefix of each port and compares them to their occurrances in the list
      port_occ_list = substr_in_list(this_port, new_val_list)
      #if the occurrance is not identical to the first or last one, it gets sliced out
      if len(port_occ_list) > 2 and current_port_string != port_occ_list[0] and current_port_string != port_occ_list[-1]:
          new_val_list = new_val_list[:counter02] + new_val_list[counter02+1:]
      else:
        counter02 += 1
    val_list[counter01] = new_val_list
    counter01 += 1
  #return val_list
  counter03 = 0
  while counter03 < len(val_list):
    counter04 = 0
    while counter04 < len(val_list[counter03]):
      current_port_string = val_list[counter03][counter04]
      time_stamp_delim = current_port_string.index(".")
      val_list[counter03][counter04] = current_port_string[:time_stamp_delim+2]
      counter04 += 1
    counter03 += 1


  #pinged_port_list = {}
  #counter01 = 0
  #while counter01 < len(key_list):
    #current_key = key_list[counter01]
    #current_val = val_list[counter01]
    #pinged_port_list[current_key] = current_val
    #counter01 += 1
  
  potential_nmap_scan_list = []
  counter05 = 0
  while counter05 < len(val_list):
    counter06 = 0
    ports_found = []
    num_of_tmstmp_violations = 0
    val_tmstmp_list = val_list[counter05]
    total_tmstmp_length = len(val_tmstmp_list)
    while counter06 < total_tmstmp_length:
      tmstmp_diff = 0
      full_string = val_tmstmp_list[counter06]
      prt_tmstmp_delim = full_string.index("-")
      port_str = full_string[:prt_tmstmp_delim]
      tmstmp_str = full_string[prt_tmstmp_delim+1:]
      if port_str not in ports_found:
        ports_found.append(port_str)
      if counter06 != 0:
        prev_fullstr = val_tmstmp_list[counter06-1]
        prev_delim = prev_fullstr.index("-")
        prev_tmstmp = prev_fullstr[prev_delim+1:]
        tmstmp_diff = float(tmstmp_str) - float(prev_tmstmp)
        if tmstmp_diff <= scan_timing_threshold:
          num_of_tmstmp_violations += 1
      counter06 += 1
    if len(ports_found) >= nmap_unique_ports and (total_tmstmp_length / num_of_tmstmp_violations) >= nmap_percentage_of_violations:
      potential_nmap_scan_list.append(key_list[counter05])
    counter05 += 1

  if potential_nmap_scan_list != 0:
    port_scan_rule_ret = []
    counter07 = 0
    while counter07 < len(potential_nmap_scan_list):
      source_addr_ret = potential_nmap_scan_list[counter07][:(potential_nmap_scan_list[counter07].index(":"))]
      dest_addr_ret = potential_nmap_scan_list[counter07][(potential_nmap_scan_list[counter07].index(":"))+1:]
      port_scan_rule_ret.append("drop any " + source_addr_ret + " any -> " + dest_addr_ret + ' any (msg: "Known port-scanning address ' + source_addr_ret + '"; sid 1000001')
      counter07 += 1
  return port_scan_rule_ret





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
  #adds port scan detection rules
  counter01 = 0
  scan_rules = nmap_scan_check(pinged_port_list)
  while counter01 < len(scan_rules):
    snort_rules.append(scan_rules[counter01])
    occurences.append("N/A")
    counter01 += 1
  #
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
  file_name = "Project test.pcapng"
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