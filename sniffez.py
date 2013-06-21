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
import MySQLdb as mdb

# set local database
db_local_user = 'root'
db_local_pass = 'db_pass'
db_local_address = 'localhost'
db_local_schema = 'sniffez'
con = None
con = mdb.connect(db_local_address, db_local_user,db_local_pass, db_local_schema);
cur = con.cursor()
sql="INSERT INTO log(log_data) VALUES (%s)"
x=0
value_regex = re.compile("GET.*\\\\r\\\\n\\\\r\\\\n")

def sniffer():
	while True:
		a=sniff(filter="tcp port 80 and ip[2:2] > 40 and tcp[tcpflags] & tcp-push != 0 and dst port 80",count=1)
		base_request = value_regex.findall(str(a))
		request_str = [request_str.replace('\\r\\n','\n') for request_str in base_request]
		if request_str:
			try:
				cur.execute(sql,(request_str))
				con.commit()
				print request_str
			except mdb.Error as e:
				print '\033[1;31m[FAIL] Please check\033[1;m', 'Error %d: %s' % (e.args[0], e.args[1])

sniffer()

