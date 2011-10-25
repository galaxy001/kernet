#!/usr/bin/env python

import urllib2
import socket 

domains = open("domain-list.txt", "r").read().split('\n')
for d in domains:
    try:
        urllib2.urlopen(d, None, 10).read()
    except Exception, err:
        print err

