#!/usr/bin/env python
# Sniffez v0.2a
# Created by: Cristian 'Tmap' Mariolini
# Mail: cristian [at] mariolini [dot] net
# Twitter: @mariolinic
# Web: https://www.mariolini.net

from scapy.all import *
import re
import csv
import sys
x=0
value_regex = re.compile("GET.*\\\\r\\\\n\\\\r\\\\n")
out_file = csv.writer(open('file_out.csv', "wb"))

def sniffer():
	try:
		while True:
			a=sniff(filter="tcp port 80 and ip[2:2] > 40 and tcp[tcpflags] & tcp-push != 0 and dst port 80",count=1)
			m = value_regex.findall(str(a))
			if m:
				out_file.writerow(m)
			status_sniff = raw_input('Running...[type "stop" to quit]: ')
			if status_sniff == 'stop':
				exit(1)
	except:
		pass
sniffer()
