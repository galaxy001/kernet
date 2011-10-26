#!/usr/bin/env python

import sys
import base64
import urllib2
import string
import itertools
import socket
from operator import itemgetter, attrgetter
    
if __name__ == "__main__":
    filename = "domain-list.txt"
    if (len(sys.argv) > 1) :
        filename = sys.argv[1]

    hosts = open("hosts", "r")

    ipCache = {}
    lines = hosts.read().split('\n')
    for l in lines:
        if len(l) < 3:
            continue
        ip, addr = l.split('\t')
        ipCache[addr] = ip
    #print ipCache
    hosts.close()

    dns_lost = open("no-dns-record.txt", "r")
    badDomains = {}
    lines = dns_lost.read().split('\n')
    for l in lines:
        if len(l) < 3:
            continue
        badDomains[l] = 1

    domains = open(filename, "r").read().split('\n')
    hosts = open("hosts", "a")

    ipMap = {} 
    for d in domains:
        if len(d) < 3:
            continue
        
        if (d in badDomains):
            continue

        if (d in ipCache):
            ip = ipCache[d]
        else: 
            try:
                ip = socket.gethostbyname(d)
            except:
                print '#unable to resolve ' + d
                continue
            hosts.write(ip + "\t" + d + "\n")
            hosts.flush()
            ipCache[d] = ip

        print d + "\t" + ip
        if ip not in ipMap:
            ipMap[ip] = 0
        ipMap[ip] += 1

    #print ipMap
    b24prefixCounter = {}
    for ip in ipMap:
        b24prefix = ip.rsplit('.', 1)[0]
        if b24prefix not in b24prefixCounter:
            b24prefixCounter[b24prefix] = 0 
            
        b24prefixCounter[b24prefix] += ipMap[ip]
    ipList = []
    for b24prefix in b24prefixCounter:
        ipList.append([b24prefix, b24prefixCounter[b24prefix]])
    print sorted(ipList, key=itemgetter(1))
    ipList.reverse()

    rangeList = []
    for i in ipList:
        rangeList.append(i[0])
    print rangeList
