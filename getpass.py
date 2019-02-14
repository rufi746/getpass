#!/usr/bin/env python
import nmap 
import os
import subprocess
import re
import time
import xml.etree.ElementTree as ET
#Set CIDR notation (192.168.0.2/24), range (192.168.2.3-192.168.2.65), sigle IP (192.168.0.1)
def nmapscan(ip, args):
	files = "./nmapscans"
	#print ip 
	#print args
	#rex = r'(?:^|\W.)Host is up(?:$|\W)'
	#rexip = r'\d+\.\d+\.\d+\.\d+'
	scan = os.system('nmap '+args+' '+files+' '+ip)
	parsescan(files)
	#scan = subprocess.Popen(['nmap', args, ip], stdout=subprocess.PIPE)
	#for line in scan.stdout:
	#	getup = line.strip()
	#	for up in re.finditer(rexip, getup):
	#		#print line
	#		print up.group()
	#	for lines in re.finditer(rex, getup): 
	#		print lines.group()
	#		print " " 			
def main():
	bruteF = '-sC -sV -vv -A --script *-brute.nse -oG'
	ms17 = '-sS -vv -A --script smb-vuln-ms17-010.nse -oG'
	livehosts = '-Pn -PS -PE -oG'
	inputlist = '-sS -sV -vv -A -oG'
	common = '-F -A -oG'
	smbv1 = '-Pn -p139,445 --script smb-protocols.nse' 
	print " "
	print "Select type of scan" 
	print "1. Brute force scan" 
	print "2. MS17-010"
	print "3. Discover Live Hosts" 
	print "4. Common Ports (Fast)"
	print " " 
	choice = raw_input("Select a number for type of scan(1-4): ")
	print " " 
	rngs = raw_input("Enter network to scan, example(192.168.0.2/24, 192.168.2.3-192.168.2.65, 192.168.0.1): ")
	if choice == "1":
		nmapscan(rngs, bruteF)
	elif choice == "2":
		nmapscan(rngs, ms17)
	elif choice == "3":
		nmapscan(rngs, livehosts)
	elif choice == "4":
		nmapscan(rngs, common)
	elif choice == "5":
		print "Going back to start over"
		main()				
	else: 
		print " oh no" 
def parsescn(f):
	#print "1" 
	rex = r'(\d+)\/(\w+)\/(\w+)\/\/(\w+)'
	rex2 = r'(?i)Host:\s(\S+)'
	rex3 = r'(\d+?)\/'
	a = open(f, "r")
	tree = ET.parse(f)
	root = tree.getroot()
	#print root
	#lines_seen = set()
	for host in root.iter('address'):
		#print host.get('addr')
		for elem in root.iter('elem'):
			#print elem.text
			if "SMBv1" in elem.text:
				print elem.text
				a = host.get('addr')
				if a not in elem.text:
					print a
		#addr = i.get('addr')
		#print addr
		#print elem.text
	##for e in root.iter('script'):
	##	print e.tag, e.attrib
	##	print child.text		
		#smbd = i.get('dialects')
		#print smbd
	#for line in a: 
	#	if "SMBv1" in line: 
	#		print line
	#	for host in re.finditer(rex2, a):
	#		ip = host.group(1)
	#		print ip
	#	for status in re.finditer(rex, line):
	#		opn = status.group()				
	#		if "open" in opn:
	#			print opn
	#			opend = ip + " " + opn
	#			print opend
					#for port in re.finditer(rex3, opend):
					#	oport = port.group(1)
					#print oport
					#ports1 = ", ".join(oport)	
					#print ports1
#main()
parsescn("./testips1.xml")
