#!/usr/bin/env python
import socket

IPs = []

for i in range(1, 24):
	for j in range(1, 8):
		host = "tc.v%d.cache%d.c.youtube.com" % (i, j)
		ip = socket.gethostbyname(host)
		print "Host: " + host + "\tIP: " + ip
		IPs.append(ip)