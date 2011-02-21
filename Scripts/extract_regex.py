#!/usr/bin/env python

import sys
import base64
import urllib2
import string
import itertools

GFWRulesURL = "http://autoproxy-gfwlist.googlecode.com/svn/trunk/gfwlist.txt"

def stringBetweenStrings(base, start, end):
    s_pos = base.find(start)
    if (s_pos < 0):
        return None
    
    e_pos = base.find(end, s_pos)
    if (e_pos < 0):
        return None
    
    return base[s_pos+len(start):e_pos]

def fetchPac():
    #req = urllib2.urlopen(GFWRulesURL)
    #response = req.read()
    f = open("pac.txt", "r")
    response = f.read()
    f.close()
    return base64.b64decode(stringBetweenStrings(response, '("', '")'))

def fetchRules():
    #req = urllib2.urlopen(GFWRulesURL)
    #response = req.read()
    #return base64.b64decode(response)
    f = open("gfwlist.txt", "r")
    return f.read()

def applyFilterToList(list):
    retLines = []
    for line in list.splitlines():
        if line.strip() == "": # empty line
            continue
        if line.startswith("[") or line.startswith("!"): # comments
            continue
        retLines.append(line.strip())
    return retLines

def applyFilterToPac(pac):
    retLines = []
    for line in pac.splitlines():
        l = line.strip()
        if l == "":
            continue
        if not l.startswith("if("):
            continue
        if l.endswith("return DEFAULT;"):
            continue
        if l.find("appspot") != -1:
            continue
        if l.find("google") != -1:
            continue
        if l.find("wikipedia") != -1:
            continue
        retLines.append(l)
    return retLines

def extractRules(list):
    pass

def extractPac(pac):
    line_ctr = 0
    ret = []
    for line in pac:
        line_ctr = line_ctr+1
        l = string.replace(line, "/i.test(url)) return PROXY;", "")
        l = string.replace(l, "if(/", "")
        p = l.split("\/\/")
        l = p[len(p)-1]
        p = l.split("?")
        t = p[len(p)-1].split("\/")[0]
        p[len(p)-1] = t
        l = "?".join(p)
        l = l.split(".*")[0]
        ret.append(l)
    return ret

def printList(list):
    line_ctr = 0
    for line in list:
        line_ctr = line_ctr + 1
        print str(line_ctr) + "\t" + line
        
def main():
    #    fetchedList = fetchRules()
    #moderatedLines = applyFilterToList(fetchedList)
    # print moderatedLines
    pac = fetchPac()
    pac = applyFilterToPac(pac)
    rules = extractPac(pac)
    rules = sorted(set(rules))
    printList(rules)
    
if __name__ == "__main__":
    main()