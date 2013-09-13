#!/usr/bin/env python
# Sniffez v0.2b sqlite3
# Created by: Cristian 'Tmap' Mariolini
# Mail: cristian [at] mariolini [dot] net
# Twitter: @mariolinic
# Web: https://www.mariolini.net

from scapy.all import *
import re
import csv
import sys
import sqlite3
con=sqlite3.connect('sniffez.db')
cur=con.cursor()
sql="INSERT INTO log(log_data) VALUES (%s)"
x=0
value_regex = re.compile("GET.*\\\\r\\\\n\\\\r\\\\n")

def sniffer():
	global x
	while x<10:
		a=sniff(filter="tcp port 80 and ip[2:2] > 40 and tcp[tcpflags] & tcp-push != 0 and dst port 80",count=1)
		base_request = value_regex.findall(str(a))
		request_str = [request_str.replace('\\r\\n','\n') for request_str in base_request]
		if request_str:
			try:
				cur.execute(sql,(request_str))
				print request_str
			except sqlite3.Error as e:
				print '\033[1;31m[FAIL] Please check\033[1;m', 'Error %d: %s' % (e.args[0], e.args[1])
		x=x+1
sniffer()


