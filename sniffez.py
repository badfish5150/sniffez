#!/usr/bin/env python
# Sniffez v0.2c sqlite3
# Created by: Cristian 'Tmap' Mariolini
# Mail: cristian [at] mariolini [dot] net
# Twitter: @mariolinic
# Web: https://www.mariolini.net

from scapy.all import *
import re
import csv
import sys
import sqlite3
import datetime
import time
con=sqlite3.connect('sniffez.db')
cur=con.cursor()
def create_db():
	global cur
	try:
		create_db="""CREATE TABLE "sniffez_log" (
			"log_id" INTEGER PRIMARY KEY DEFAULT (1),
			"log_time" INTEGER NOT NULL,
			"log_data" TEXT NOT NULL
		);"""
		cur.execute(create_db)
	except sqlite3.Error as e:
		print e.args[0]


def sniffer():
	x=0
	while x<10:
		a=sniff(filter="tcp port 80 and ip[2:2] > 40 and tcp[tcpflags] & tcp-push != 0 and dst port 80",count=1)
		parse_get(a)
	x=x+1
def parse_get(a):
	get_regex = re.compile("GET.*\\\\r\\\\n\\\\r\\\\n")
	base_request = get_regex.findall(str(a))
	request_str = [request_str.replace('\\r\\n','\n') for request_str in base_request]
	print request_str
def parse_post(a):
	post_regex = re.compile ("POST.*\\\\r\\\\n\\\\r\\\\n.*\' \|>>>>\]")
	base_request = post_regex.findall(str(a))
	request_str = [request_str.replace('\\r\\n','\n') for request_str in base_request]
	

sniffer()	
