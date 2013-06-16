#!/usr/bin/env python
# Sniffez v0.1
# Created by: Cristian 'Tmap' Mariolini
# Mail: cristian [at] mariolini [dot] net
# Twitter: @mariolinisc
# Web: https://www.mariolini.net

from scapy.all import *
import re
import csv
def sniffer():
	x=0
	value_regex = re.compile("GET.*\\\\r\\\\n\\\\r\\\\n")
	out_file = csv.writer(open('file_out.csv', "wb"))
	while True:
		try:
			a=sniff(filter="tcp port 80 and ip[2:2] > 40 and tcp[tcpflags] & tcp-push != 0 and dst port 80",count=1)
			m = value_regex.findall(str(a))
			if m:
				print m
				out_file.writerow(m)
			else:
				pass
		except KeyboardInterrupt:
			exit(0)
sniffer()
