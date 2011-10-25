#!/usr/bin/env python

import sys
import base64
import urllib2
import string
import itertools
import socket
    
if __name__ == "__main__":
    hosts = open("hosts", "w")
    domains = open("domain-list.txt", "r").read().split('\n')
    ipMap = {}

    for d in domains:
        try:
            ip = socket.gethostbyname(d)
        except:
            print '#unable to resolve ' + d
            continue
        hosts.write(ip + "\t" + d + "\n")
        hosts.flush()

        print d + "\t" + ip
        if (ip in ipMap):
            ipMap[ip] += 1
        else :
            ipMap[ip] = 0

    print ipMap

