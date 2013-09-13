#!/usr/bin/env python
# Sniffez v0.2c sqlite3
# Created by: Cristian 'Tmap' Mariolini
# Mail: cristian [at] mariolini [dot] net
# Twitter: @mariolinic
# Web: https://www.mariolini.net
# NOTE . YOU NEED TO CREATE A SQLITE DATABASE CALLED "sniffez.db"  IN THE SAME DIRECTORY AS SNIFFEZ
# CREATE THE DB WITH 2 COLUMNS log_id (PK AUTOINCREMENTAL, NOT NULL) AND log_data (TEXT)
from scapy.all import *
import re
import csv
import sys
import sqlite3
con=sqlite3.connect('sniffez.db')
cur=con.cursor()

x=0
value_regex = re.compile("GET.*\\\\r\\\\n\\\\r\\\\n")


def sniffer():
	global x
	while x<100:
		a=sniff(filter="tcp port 80 and ip[2:2] > 40 and tcp[tcpflags] & tcp-push != 0 and dst port 80",count=1)
		base_request = value_regex.findall(str(a))
		request_str = [request_str.replace('\\r\\n','\n') for request_str in base_request]
		if request_str:
			try:
				cur.execute("""INSERT INTO sniffez_log VALUES (NULL,?)""",(request_str))
				con.commit()
				print request_str[0]
				
			except sqlite3.Error as e:
				print e.args[0]
		x=x+1
sniffer()

