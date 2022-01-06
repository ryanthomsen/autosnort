#!/usr/bin/env python3

### IMPORT STATEMENTS ###
import sys
import os
import socket
import configparser
from pigget import *
from autogui import *
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
### HELPER FUNCTIONS ###


#Method to take an ip in a string format i.e. "192.56.168.0"
#and convert it to a list format i.e. [192,56,168,0]
def ip2list(ipstring):
  stringbits = ipstring.split(".")
  ip = []
  for num in stringbits:
    num = str(num)
    num = re.sub("[^0-9]", "", num)
    num = int(num)
    ip.append(num)
  return ip

#Method to take an ip in a list format i.e. [192,56,168,0]
#and convert it to a string format i.e. "192.56.168.0"
def iplist2string(iplist):
  ip = ""
  for num in iplist:
    num = str(num)
    num = re.sub("[^0-9]", "", num)
    ip += num
    ip += (".")
  ip = ip[0:(len(ip)-1)]
  return ip

#Temp magic nums
scan_timing_threshold = 0.1
nmap_unique_ports = 15
nmap_percentage_of_violations = 0.75

def numsan(stringnum):
  stringnum = str(stringnum)
  stringnum = re.sub("[^0-9]", "", stringnum)
  stringnum = int(stringnum)
  return stringnum

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
  #NMAP Variables
  global scan_timing_threshold
  global private_port_ranges
  global whitelisted_ip_addresses
  global nmap_unique_ports
  global nmap_percentage_of_violations
  global SAVE_OUTPUT
# private_port_ranges = ["1025-65535"]

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
  SAVE_OUTPUT = parser.getboolean("Output", "Save_Output")
  #Loading nmap settings:
  scan_timing_threshold = float(parser.get("Nmap", "scan_timing_threshold"))
  nmap_unique_ports = int(parser.get("Nmap", "nmap_unique_ports"))
  nmap_percentage_of_violations = float(parser.get("Nmap", "nmap_percentage_of_violations"))


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


#Listen Mode
def listen4pigs(numpigs):
    numpigs = numsan(numpigs)
    spacket_list = sniff(count=numpigs)
    return spacket_list


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
  window_size = singlepigget.tcp_window_size
  flags = singlepigget.flags
  #Checks if suspicious ports are used
  if tcpsourceport in BAD_PORTS:
    suggestion = "drop TCP " + str(singlepigget.ipsource) + ' ' + str(tcpsourceport) + ' -> any any (msg: "Suspicious activity from Port ' + str(tcpsourceport) + '"; sid'
    if tcpdestport == BAD_PORTS:
      suggestion = "drop TCP any any -> " + str(singlepigget.ipdest) + ' ' + str(tcpdestport) + ' (msg: "Suspicious Port activity to Port ' + str(tcpdestport) + '"; sid'
  #Checks if the window size is too high
  if window_size > 65535:
    suggestion = "drop TCP " + str(singlepigget.ipsource) + " any -> " + str(singlepigget.ipdest) + " " + str(tcpdestport) + " (window:" + str(window_size) + '; msg: "Invalid window size; sid'
  #Checks for an x-mas tree attack
  if str(flags) == "FPU":
    suggestion = 'drop TCP any any -> any any (flags:UPF; msg: "Attempted X-Mas tree attack"; sid'
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
      suggestion = "drop UDP " + iplist2string(ip_source) + ' any -> ' + iplist2string(ip_dest) + ' 67 (msg: "Rogue DHCP request from ' + iplist2string(ip_source) + '"; sid'
    
    #Rule to catch DNS requests to servers outside the subnet.
    if ip_dest not in subnet and udpsourceport == 67 and udpdestport == 68:
      suggestion = "drop UDP " + iplist2string(ip_source) + ' 67 -> ' + iplist2string(ip_dest) + ' 68 (msg: "DHCP Request made to ' + iplist2string(ip_dest) + ' which is outside the subnet mask."; sid'
    
    #Rule to catch swapped DHCP ports
    if udpsourceport == 68 and udpdestport == 67 and ip_dest in dhcp_servers:
      suggestion = "drop UDP " + iplist2string(ip_source) + '68 -> ' + iplist2string(ip_dest) + ' 67 (msg: "Cannot connect to DHCP server on port 67."; sid'

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
      port_scan_rule_ret.append("drop any " + source_addr_ret + " any -> " + dest_addr_ret + ' any (msg: "Known port-scanning address ' + source_addr_ret + '"; sid')
      counter07 += 1
  return port_scan_rule_ret


def run_pcap(pcap):
  global subnet
  subnet = subnet_24(Network_IP)
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
  nmap_rules = nmap_scan_check(pinged_port_list)
  counter01 = 0
  while counter01 < len(nmap_rules):
    snort_rules.append(nmap_rules[counter01])
    occurences.append(1)
    counter01 += 1
  global PRINTPCKT
  print(str(PRINTPCKT))
  if(PRINTPCKT):
    printlist(packet_list)
  print("\n\n")
  print("Snort Rule Suggestions: ")
  for index in range(0, len(snort_rules), 1):
    print(snort_rules[index] + ":" + str(SID_START) + ";)\n")
    SID_START += 1
    print("# of Packets Flagged: " + str(occurences[index]))
    print("______________________________________________")