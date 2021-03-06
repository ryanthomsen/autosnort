#!/usr/bin/env python3

### IMPORT STATEMENTS ###
from re import split
import sys
import os
import socket
import configparser
from time import gmtime
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import *
from time import gmtime, localtime

#MAGIC NUMBERS
GM_T = True
PROTO_TABLE = table = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
pinged_port_list = {}

#Function to read private port ranges from config file for use in pigget
def private_ranger():
    parser = configparser.ConfigParser()
    parser.read("config.txt")
    private_port_ranges = parser.get("Nmap", "private_port_ranges")
    return private_port_ranges


#Takes in a gm timestamp string and returns a list of sperated values
def time_parse(gm_timestamp):
    ret_list = []
    while "=" in gm_timestamp:
        delim01 = gm_timestamp.index("=") + 1
        if "," in gm_timestamp:
            delim02 = gm_timestamp.index(",")
        else: delim02 = gm_timestamp.index(")")
        ret_list.append(gm_timestamp[delim01:delim02])
        gm_timestamp = gm_timestamp[delim02+1:]
    return ret_list

#Check against private port ranges (Used in nmap checker)
def port_range_check(port_num) -> int:
  private_port_ranges = [private_ranger()]
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

#Pigget object for easier handling of packets than scapy module
class Pigget:
    def __init__(self, singlepacket, packetnum):
      global pinged_port_list
      self.PPL = pinged_port_list
      self.packetnum = packetnum
      #Assigns IP variables to pigget if they exist within the packet
      if IP in singlepacket:
        self.proto = singlepacket[IP].proto
        self.ipsource = singlepacket[IP].src
        self.ipdest = singlepacket[IP].dst
        self.timestamp = singlepacket.time
        #Assigns TCP variables to pigget if they exist within the packet
        if TCP in singlepacket:
            self.tcpsourceport = singlepacket[TCP].sport
            self.tcpdestport = singlepacket[TCP].dport
            self.tcp_window_size = singlepacket[TCP].window
            self.flags = singlepacket[TCP].flags
            if self.tcpdestport == 80:
                # Checks if packet has payload
                if singlepacket.haslayer(HTTPRequest):
                    #rawload = singlepacket[0][0][Raw].load
                    self.http_method = singlepacket[HTTPRequest].Method
            #Adds TCP packet to nmap dictionary
            if port_range_check(self.tcpdestport):
                source_dest_pair = self.ipsource + ":" + self.ipdest
                str_port_add = (str(self.tcpdestport) + "-" + str(self.timestamp))
                if source_dest_pair in pinged_port_list:
                    pinged_port_list[source_dest_pair].append(str_port_add)
                else: pinged_port_list[source_dest_pair] = [str_port_add]
        #Assigns UDP variables to pigget if they exist within the packet
        if UDP in singlepacket:
            self.udpsrcport = singlepacket[UDP].sport
            self.udpdestport = singlepacket[UDP].dport
            #Adds UDP packet to nmap dictionary
            if port_range_check(self.udpdestport):
                source_dest_pair = self.ipsource + ":" + self.ipdest
                str_port_add = (str(self.udpdestport) + "-" + str(self.timestamp))
                if source_dest_pair in pinged_port_list:
                    pinged_port_list[source_dest_pair].append(str_port_add)
                else: pinged_port_list[source_dest_pair] = [str_port_add]
        #Assigns ICMP variables to pigget if they exist within the packet
        if ICMP in singlepacket:
            self.icmptype = singlepacket[ICMP].type
          # Print DNS Hostname
	    # Check if DNS is present in the packet
        if DNSQR in singlepacket:
            self.hostname = singlepacket[DNSQR].qname
        if DNSRR in singlepacket:
            self.hostaddr = singlepacket[DNSRR].rdata
            #self.recordtype = singlepacket[DNSRR].qtype

    #Definition of how to print our Pigget object
    def __str__(self):
        result = ''
        result+=("Packet Number: " + str(self.packetnum) + "\n")
        if hasattr(self, 'proto'):
            result+=("Protocol: " + PROTO_TABLE[self.proto] + "\n")
        # Print IP source and destination
        # Check if the IP layer is present in the packet
        if hasattr(self, 'ipsource') and hasattr(self, 'ipdest'):
            result += ("IP Source: " + str(self.ipsource) + " | IP Dest: " + str(self.ipdest) + "\n")
        #Print Timestamp if avaiable
        if hasattr(self, 'timestamp'):
            if GM_T:
                if(isinstance(self.timestamp, float) or isinstance(self.timestamp, EDecimal)):
                    self.timestamp = str(gmtime(float(self.timestamp)))
                    self.timestamp = time_parse(self.timestamp)
                result += ("Time: " + str(self.timestamp[3]).zfill(2) + ":" + str(self.timestamp[4]).zfill(2) + ":" + str(self.timestamp[5]).zfill(2) + " GMT, " + str(self.timestamp[1]) + "/" + str(self.timestamp[2]) + "/" + str(self.timestamp[0]) + "\n")
            elif not GM_T:
                result += ("Epoch Time: " + str(self.timestamp) + "\n")


        # Print TCP source port and destination port
        # Check if TCP is present in the packet
        if hasattr(self, 'tcpsourceport') + hasattr(self, 'tcpdestport'):
            result += ("TCP Source Port: " + str(self.tcpsourceport) +
                       " | TCP Dest Port: " + str(self.tcpdestport) + "\n")
            #Prints the window size
            result += ("Window size: " + str(self.tcp_window_size) + "\n")
            #Prints flags?
            result += ("Flags: " + str(self.flags) + "\n")
            # Print HTTP Request Type
            # Check if HTTP is present in the packet
            if hasattr(self, 'http_method'):
            # Checks if packet has payload
                #rawload = singlepacket[0][0][Raw].load
                result += ("HTTP Request Type: " +
                           str(self.http_method) + "\n")

        # Print DNS Hostname
        # Check if DNS is present in the packet
        if hasattr(self, 'hostname'):
            result += ("DNS HostName: " + str(self.hostname) + "\n")

        # Print DNS Host Address
        # Check if Scapy is able to load additional DNS information
        if hasattr(self, 'hostaddr'):
            # + " | TCP Dest Port: " + str(self.recordtype))
            result += ("DNS Host Address: " + str(self.hostaddr) + "\n")
        
        # Print UDP source port and UDP destination port
        # Check if UDP is present in the packet
        if hasattr(self, 'udpdestport') and hasattr(self, 'udpsrcport'):
            result += ("UDP Source Port: " + str(self.udpsrcport) +
                       " | UDP Dest Port: " + str(self.udpdestport) + "\n")
        # Print ICMP Type:
        # Check if ICMP is present in the packet
        if  hasattr(self, 'icmptype'):
            result += ("ICMP Type: " + str(self.icmptype) + "\n")
        return result