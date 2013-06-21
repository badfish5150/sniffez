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


x=0
value_regex = re.compile("GET.*\\\\r\\\\n\\\\r\\\\n")

def sniffer():
	# set local database
	db_local_user = 'db_user'
	db_local_pass = 'yourpwd'
	db_local_address = 'localhost'
	db_local_schema = 'sniffez'
	con = None
	con = mdb.connect(db_local_address, db_local_user,db_local_pass, db_local_schema);
	cur = con.cursor()
	sql="INSERT INTO log(log_data) VALUES (%s)"
	while True:
		a=sniff(filter="tcp port 80 and ip[2:2] > 40 and tcp[tcpflags] & tcp-push != 0 and dst port 80",count=1)
		m = value_regex.findall(str(a))
		if m:
			try:
				cur.execute(sql,(m))
				con.commit()
				print m
			except mdb.Error as e:
				print '\033[1;31m[FAIL] Please check\033[1;m', 'Error %d: %s' % (e.args[0], e.args[1])

sniffer()

