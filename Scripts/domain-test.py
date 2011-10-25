#!/usr/bin/env python

import urllib2
import socket 

domains = open("domain-list.txt", "r").read().split('\n')
freed = open("freed.txt", "w")
reset = open("reset.txt", "w")
timeout = open("timeout.txt", "w")
wtf = open("wtf.txt", "w")

for d in domains:
    try:
        urllib2.urlopen("http://"+d, None, 10).read()
        freed.write(d+"\n")
        freed.flush()
    except Exception, msg:
        err = str(msg) + "\n"
        print d + ": " + err
        if err.find("reset") >= 0:
            reset.write(d+"\n")
            reset.flush()
            continue
        if err.find("timed out") >= 0:
            timeout.write(d+"\n")
            timeout.flush()
            continue
        wtf.write(d + ": "+ err)
        wtf.flush()

        

