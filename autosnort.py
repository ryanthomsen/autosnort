#!/usr/bin/env python3
#Main file running the logic behind autosnort
#Calls appropriate methods from other files
#Depending on options used
#Currently only works in a bash style terminal
### IMPORT STATEMENTS ###
import sys
import os
import socket
import configparser
from pigget import *
from autogui import *
from autorule import *
from time import gmtime
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import *
from time import gmtime, localtime

### MAIN FUNCTION ###
#Looks for specific options o determine what mode to run autosnort in
def main():
    recognized = False
    read_conf() #Read config file to prepare for running autosnort
    if len(sys.argv) == 2:
      #Gui Option checker
      if sys.argv[1] in "--gui" and "-" in sys.argv[1]:
        recognized = True
        load_GUI()
      #Help Option checker
      elif sys.argv[1] in "--help" and "-" in sys.argv[1]:
        print("Welcome to Auto Snort!\n"
              "This is a tool for automatically suggesting snort rules.\n"
              "Options available are\n"
              "Open pcap/pigget.txt file for analysis     ./autosnort -f filename\nor ./autosnort --file filename\n"
              "Listen for x # of packets then analyze         ./autosnort -l #ofpackets\nor ./autosnort --listen\n"
              #"View specific packet(s) info in a pigget.txt file (Coming soon)    ./autosnort -p piggetfilename packet(s)num2view\n"
              "Open autosnort GUI     ./autosnort -g\nor ./autosnort --options\n"
              "Open autosnort settings ./autosnort -o\nor ./autosnort --options\n"
              "Open autosnort help page    ./autosnort -\nor ./autosnort --help\n"
              "Script made by Ryan Thomsen and Matt Ages\n"
              "Pigget.txt file is just a text file saved by Autosnort."
              )
      #Options/Config settings checker
      elif sys.argv[1] in "--options" and "-" in sys.argv[1]:
        open_conf()
        recognized = True
    #Open File Option
    elif len(sys.argv) == 3:
      if sys.argv[1] in "--file" and "-" in sys.argv[1]:
        recognized = True
        file_name = sys.argv[2]
        if os.path.isfile(file_name):
          scapy_cap = rdpcap(file_name)
        else:
          print("Error:", file_name, "doesn't not exist.")
          sys.exit(1)
        tupleout = run_pcap(scapy_cap)
        snort_rules = tupleout[0]
        occurences = tupleout[1]
        print_rules(snort_rules, occurences)
    
    #Listen Mode Option
      elif sys.argv[1] in "--listen" and "-" in sys.argv[1]:
        recognized = True
        num_pack = int(sys.argv[2])
        pcap1 = listen4pigs(num_pack)
        tupleout = run_pcap(pcap1)
        snort_rules = tupleout[0]
        occurences = tupleout[1]
        print_rules(snort_rules, occurences)
    #Planned packet reader functionality, currently unimplemented
    elif len(sys.argv) == 4:
      if sys.argv[1] == "-p":
        recognized = True
        print("Coming Soon. Need Sleep first.")
      #    file_name = sys.argv[2]
      #    if(".txt" == file_name[-4:len(file_name)]):
      #        f=open(file_name)
      #        f.readlines()
      #        f.close()
      #   else:
      #   print("Must be a pigget file followed by a packet number / range of packet numbers.")
      #   num_pack = sys.argv[3]
      #if ("-" in num_pack):
      #   plist = num_pack.split("-")
      #   while(plist[0] < plist[1]):
      #     print(plist[0])
      #     plist[0] = plist[0] + 1
      #   pcap1 = listen4pigs(num_pack)
      #   run_pcap(pcap1)
    #If none of the above options were recognized, suggests opening help menu
    if(not recognized):
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



### DUNDER CHECK ###
if __name__ == "__main__":
  main()
