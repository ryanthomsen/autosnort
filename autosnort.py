#!/usr/bin/env python3

### IMPORT STATEMENTS ###
import sys


### HELPER FUNCTIONS (IF NECESSARY) ###
def HelperMethods(file):
  lines_list = file.readlines()


### MAIN FUNCTION ###
def main():
  file_name = sys.argv[1]
  open_file = open(file_name)
  HelperMethods(open_file)
  open_file.close()


### DUNDER CHECK ###
if __name__ == "__main__":
  main()
