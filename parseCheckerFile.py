#!/usr/bin/python
# Malware VT Finder by Melissa Augustine
# Use this after running urlChecker.py, point it at the VirusTotalResults file and it will look for items which have been found as 'malware'... useful when you are dealing with large quantities of submissions

import sys, getopt
import os

def main(argv):
	inputfile = ''
	outputfile = ''
	try:
		opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
	except getopt.GetoptError:
		print 'parseCheckerFile.py -i <inputfile> -o <outputfile>'
        	sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print 'parseCheckerFile.py -i <inputfile> -o <outputfile>'
         		sys.exit()
      		elif opt in ("-i", "--ifile"):
        		 inputfile = arg
      		elif opt in ("-o", "--ofile"):
         		outputfile = arg

	with open(inputfile, "r") as f:
    		searchlines = f.readlines()
		for i, line in enumerate(searchlines):
    			if "IP/Domain" in line: 
				base = i
				for l in searchlines[base:base+16]: 					
					if "malware" in l:
							out = open(outputfile, "a")
							out.write(line + "->" + l+"\n")
							out.close()
	if not os.path.exists(outputfile):
		print "No malicious hits found"

					
											
					
					

if __name__ == "__main__":
   main(sys.argv[1:])
