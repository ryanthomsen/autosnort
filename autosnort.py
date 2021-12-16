#!/usr/bin/env python3

### IMPORT STATEMENTS ###
import sys
import os
import scapy.all as scapy


### HELPER FUNCTIONS (IF NECESSARY) ###
def HelperMethods(pcap):
  for i in range(0,20):
    print(str(i) + " : ")
    pcap[i].summary
    print("\n\n")
  

### MAIN FUNCTION ###
def main():
  #file_name = sys.argv[1]
  file_name = "Project test.pcapng"
  # Check if pcap file exists
  # if os.path.isfile(file_name):
  if os.path.isfile(file_name):
    scapy_cap = scapy.rdpcap(file_name)
  else:
    print("Error:", file_name, "doesn't not exist.")
    sys.exit(1)
  #open_file = open(file_name)
  HelperMethods(scapy_cap)
  #open_file.close()


### DUNDER CHECK ###
if __name__ == "__main__":
  main()
