#!/usr/bin/python
# URL Checker Script by Melissa Augustine
# Requires VT API key! If you use the public one, be aware of the submission limitations and use time.sleep

import sys, getopt
import os
import urllib
import urllib2
import simplejson
import time

#Get the number of lines in the original file, so we know how many we have to do!
def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1

def main(argv):
	inputfile = ''
	outputDirectory = ''
	#Getting our parameters	
	try:
		opts, args = getopt.getopt(argv,"hi:o:",["iFile=","oDir="])
	except getopt.GetoptError:
		print 'urlChecker.py -i <inputFile> -o <outputDirectory>'
        	sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print 'urlChecker.py -i <inputFile> -o <outputDirectory>'
         		sys.exit()
      		elif opt in ("-i", "--iFile"):
        		 inputfile = arg
      		elif opt in ("-o", "--oDir"):
         		outputDirectory = arg

	# Checking the output directory exists
	if not os.path.isdir(outputDirectory):
		print outputDirectory, "is not a valid directory, it will be created for you :)"
		os.makedirs(outputDirectory)
		
	VTResultsPath = os.path.join(os.path.abspath(outputDirectory), "VirusTotalResults.txt")
	VTResults = open(VTResultsPath, 'a')
	linesInFile= file_len(inputfile)
	print "Items in the original file: ", linesInFile

	f = file(inputfile, "rb")
	count1=0
	for line in f.readlines():
       		print "We are now at entry ", count1
        	url = "https://www.virustotal.com/vtapi/v2/url/report"
        	parameters = {"resource": line,
		      "apikey": "<INSERT API KEY>"}
		try:        
			data = urllib.urlencode(parameters)
        		req = urllib2.Request(url, data)
        		response = urllib2.urlopen(req)
        		json = response.read()
        		response_dict = simplejson.loads(json)
        		toot = response_dict.get("positives")
       
        		if str(toot) == "None":
           	 		errorStatement = "URL not found in VirusTotal Database... \n\n"
          			base="IP/Domain: " + line 
	   			VTResults.write(base)
	   			VTResults.write(errorStatement)
           			#time.sleep(15)
			elif str(toot) == "0":
	   			errorStatement = "No hits found\n\n"
          			base="IP/Domain: " + line 
	    			VTResults.write(base)
	    			VTResults.write(errorStatement)
        		else:
            			Opera = response_dict.get("scans", {}).get("Opera", {}).get("result")
            			TrendMicro = response_dict.get("scans", {}).get("TrendMicro", {}).get("result")
            			PhishTank = response_dict.get("scans", {}).get("PhishTank", {}).get("result")
            			DrWeb = response_dict.get("scans", {}).get("Dr.Web", {}).get("result")
	    			Malcode = response_dict.get("scans", {}).get("Malc0de Database", {}).get("result")
	    			BitDefender= response_dict.get("scans", {}).get("BitDefender", {}).get("result")	
           			MalwareDomainList= response_dict.get("scans", {}).get("MalwareDomainList", {}).get("result")
         			ParetoLogic=response_dict.get("scans", {}).get("ParetoLogic", {}).get("result")
            			Avira=response_dict.get("scans", {}).get("Avira", {}).get("result")
            			GData=response_dict.get("scans", {}).get("G-Data", {}).get("result")
            			Wepawet=response_dict.get("scans", {}).get("Wepawet", {}).get("result")
            			Websense=response_dict.get("scans", {}).get("Websense ThreatSeeker", {}).get("result")
            			permalink = response_dict.get("permalink", {})

            			base="IP/Domain: " + line + "\n"
	    			numberHits = "Number of positive hits: " + str(toot) + "\n"
            			link = "Link: " + str(permalink) + "\n"
            			OperaStr = "Opera says its " + str(Opera) + "\n"
            			TrendStr = "Trend Micro says its " + str(TrendMicro) + "\n"
            			PhishStr = "PhishTank says its " + str(PhishTank) + '\n'
            			DrStr = "Dr. Web says its " + str(DrWeb) + "\n"
	    			MalcodeStr = "Malcode says its " + str(Malcode) + "\n"
            			BitStr = "BitDefender says its " + str(BitDefender) + "\n"
            			MalwareStr = "MDL says its " + str(MalwareDomainList) + '\n'
            			ParetoStr = "ParetoLogic says its " + str(ParetoLogic) + "\n"	
            			AviraStr = "Avira says its " + str(Avira) + "\n"
            			GStr = "Symantec says its " + str(GData) + "\n"
            			WepawetStr = "Wepawet says its " + str(Wepawet) + '\n'
            			WebStr = "Kaspersky says its " + str(Websense) + "\n\n"

            			VTResults.write(base)
	    			VTResults.write(numberHits)
            			VTResults.write(link)
            			VTResults.write(OperaStr)
            			VTResults.write(TrendStr)
            			VTResults.write(PhishStr)
            			VTResults.write(DrStr)
	    			VTResults.write(MalcodeStr)
            			VTResults.write(BitStr)
            			VTResults.write(MalwareStr)
           			VTResults.write(ParetoStr)
            			VTResults.write(AviraStr)
            			VTResults.write(GStr)
            			VTResults.write(WepawetStr)
            			VTResults.write(WebStr)
            			#time.sleep(15)
			count1=count1+1
        		if count1 % 50 == 0:
				print "Sleeping for a few to reset peer"
				time.sleep(15)
		#Handling errors, can add more if more arise...		
		except (AttributeError):
			print "Error... skipping ", line
			count1=count1+1
			if count1 % 50 == 0:
				print "Sleeping for a few to reset peer"
				time.sleep(15)
			pass
	VTResults.close()

if __name__ == "__main__":
   main(sys.argv[1:])
