#!/usr/bin/env python3

### IMPORT STATEMENTS ###
import sys
import os
import socket
import configparser
from pigget import *
from time import gmtime
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import *
from time import gmtime, localtime

#Read config rules
# scan_timing_threshold = 0.1
# private_port_ranges = ["1025-65535"]
# whitelisted_ip_addresses = []
# nmap_unique_ports = 15
# nmap_percentage_of_violations = 0.75

#Misc vars
packet_list = []
pinged_port_list = {}

### HELPER FUNCTIONS ###

def ip2list(ipstring):
  stringbits = ipstring.split(".")
  ip = []
  for num in stringbits:
    num = str(num)
    num = re.sub("[^0-9]", "", num)
    num = int(num)
    ip.append(num)
  return ip

def iplist2string(iplist):
  ip = ""
  for num in iplist:
    num = str(num)
    num = re.sub("[^0-9]", "", num)
    ip += num
    ip += (".")
  ip = ip[0:(len(ip)-1)]
  return ip


#Reads config.txt
def read_conf():
  global SID_START
  global BAD_PORTS
  global Network_IP
  global include_all_packets
  global include_PKT_numbers
  global EPOCH
  global Enable_WhiteList
  global PRINTPCKT
  global dhcp_servers

  parser = configparser.ConfigParser()
  parser.read("config.txt")
  SID_START = int(parser.get("Snort", "SID_START"))
  BAD_PORTS = parser.get("Snort", "BAD_PORTS")
  BAD_PORTS = BAD_PORTS.split(",")
  for num in range(0, len(BAD_PORTS)):
    BAD_PORTS[num] = int(re.sub("[^0-9]", "", BAD_PORTS[num]))
  Network_IP = parser.get("Subdomain", "Base_IP")
  Network_IP = ip2list(Network_IP)
  include_all_packets = parser.getboolean("Output", "include_all_packets")
  include_PKT_numbers = parser.getboolean("Output", "include_PKT_numbers")
  EPOCH = parser.getboolean("Time", "EPOCH")
  Enable_WhiteList = parser.getboolean("Subdomain", "Enable_WhiteList")
  PRINTPCKT = parser.getboolean("Output", "PRINTPCKT")
  dhcp_servers = parser.get("HostedServers", "dhcp_servers")
  dhcp_servers = dhcp_servers.split(",")
  snapshot_dhcp = dhcp_servers
  dhcp_servers = []
  for dhcp_server in snapshot_dhcp:
    dhcp_servers.append(ip2list(dhcp_server))



#Takes a ip address and generates a list of 256 ip's from it.
#For example... default value 192.168.1.0 generates list of addresses
#from 192.168.1.0 to 192.168.1.255
def subnet_24(ip)-> list:
  subnet = []
  max_val = ip[3] + 255
  while(ip[3] <= max_val):
    subnet.append([ip[0],ip[1], ip[2], ip[3]])
    ip[3] += 1
  subnet.append([255,255,255,255])
  subnet.append([0,0,0,0])
  return subnet


def substr_in_list(substr, inlist):
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


# def port_range_check(port_num) -> int:
#   counter = 0
#   while counter < len(private_port_ranges):
#     min_val = 0
#     max_val = 0
#     delim = 0
#     entry_str = private_port_ranges[counter]
#     #checks if the entry is a range, or single int
#     if "-" in entry_str:
#       delim = entry_str.index("-")
#       min_val = int(entry_str[:delim])
#       max_val = int(entry_str[delim+1:])
#       #checks if the port is in the range
#       if port_num in range(min_val, max_val):
#         return False
#       else:
#         counter += 1
#     else:
#       if port_num == int(entry_str):
#         return False
#       else:
#         counter += 1
#   return True


def loadP(singlepacket, counter):
  custom_packet = Pigget(singlepacket, counter)
  return custom_packet

def printlist(list):
  for item in list:
    print(item)



def tcp_rules(singlepigget) -> str:
  #Setting up basic variables
  suggestion = ''
  tcpsourceport = singlepigget.tcpsourceport
  tcpdestport = singlepigget.tcpdestport
  #Checks if suspicious ports are used
  if tcpsourceport in BAD_PORTS:
    suggestion = "drop TCP " + str(singlepigget.ipsource) + ' ' + str(tcpsourceport) + ' -> any any (msg: "Suspicious activity from Port ' + str(tcpsourceport) + '"; sid '
    if tcpdestport == BAD_PORTS:
      suggestion = "drop TCP any any -> " + str(singlepigget.ipdest) + ' ' + str(tcpdestport) + ' (msg: "Suspicious Port activity to Port ' + str(tcpdestport) + '"; sid '
  return suggestion


def udp_rules(singlepigget) -> str:
  ##Setting up basic variables
  suggestion = ''
  udpsourceport = singlepigget.udpsrcport
  udpdestport = singlepigget.udpdestport

  #DCHP Rules
  if udpdestport == 67 or udpdestport == 68 or udpsourceport == 67 or udpsourceport == 68:
    ip_source = ip2list(singlepigget.ipsource)
    ip_dest = ip2list(singlepigget.ipdest)

    #Rule to catch rogue DNS requests from outside the network subnet
    if ip_dest in subnet and udpdestport == 67 and ip_source not in subnet:
      suggestion = "drop UDP " + iplist2string(ip_source) + ' any -> ' + iplist2string(ip_dest) + ' 67 (msg: "Rogue DHCP request from ' + iplist2string(ip_source) + '"; sid '
    
    #Rule to catch DNS requests to servers outside the subnet.
    if ip_dest not in subnet and udpsourceport == 67 and udpdestport == 68:
      suggestion = "drop UDP " + iplist2string(ip_source) + ' 67 -> ' + iplist2string(ip_dest) + ' 68 (msg: "DHCP Request made to ' + iplist2string(ip_dest) + ' which is outside the subnet mask."; sid '
    
    #Rule to catch swapped DHCP ports
    if udpsourceport == 68 and udpdestport == 67 and ip_dest in dhcp_servers:
      suggestion = "drop UDP " + iplist2string(ip_source) + '68 -> ' + iplist2string(ip_dest) + ' 67 (msg: "Cannot connect to DHCP server on port 67."; sid '

  return suggestion



# Method to suggest snort rules based on packet information
def RuleMaker(singlepigget) -> list:
  suggestion = ""
  rule_list = []
  #TCP Rules
  if hasattr(singlepigget, 'tcpsourceport') + hasattr(singlepigget, 'tcpdestport'):
    suggestion = tcp_rules(singlepigget)
    if suggestion != '':
      rule_list.append(suggestion)
      suggestion = ''
  
  #UDP Rules
  if hasattr(singlepigget, 'udpsourceport') + hasattr(singlepigget, 'udpdestport'):
    suggestion = udp_rules(singlepigget)
    if suggestion != '':
      rule_list.append(suggestion)
      suggestion = ''

    
  #Return the rules
  return rule_list


def HelperMethods(pcap):
  counter = 1
  snort_rules = []
  occurences = []
  global SID_START
  for packet in pcap:
    packet = loadP(packet, counter)
    rule_list = []
    rule_list = RuleMaker(packet)
    for rule in rule_list:
      if rule not in snort_rules:
        rule = rule
        snort_rules.append(rule)
        occurences.append(1)
      elif rule in snort_rules:
        occurences[(snort_rules.index(rule))] += 1
    counter += 1
    packet_list.append(packet)
  if(PRINTPCKT):
    printlist(packet_list)
  print("\n\n")
  print("Snort Rule Suggestions: ")
  for index in range(0, len(snort_rules), 1):
    print(snort_rules[index] + str(SID_START) + ")\n")
    SID_START += 1
    print("# of Packets Flagged: " + str(occurences[index]))
    print("______________________________________________")


### MAIN FUNCTION ###
def main():
  read_conf()
  global subnet
  subnet = subnet_24(Network_IP)
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
