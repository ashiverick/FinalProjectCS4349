#!/usr/bin/env python

import dpkt
import sys #, socket,  random

from datetime import datetime


try:
    file = open('test-2.pcap', 'rb') 
    pcap = dpkt.pcap.Reader(file)
    print("PCAP file opened and read \n")
except (IOError, KeyError):
    print("Could not open file!")
    sys.exit(-1)

inc = 0
ts1 = 0
ts2 = 0
firsttimestamp = 0
lowestport = 1000000
highestport = 0

print("##########################################################\n")
print("#1 Scan\n")

for ts, buf in pcap:
    if inc == 0:
        firsttimestamp = ts
        print("First time stamp: ", firsttimestamp)
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.Unpack.Error, IndexError):
        continue

    ip = eth.data
    if not ip:
        continue
    #print("IP Data: ", ip, '\n')
    
    tcp = ip.data
    if type(tcp) != dpkt.tcp.TCP:
        continue
    #print("TCP Data: ", tcp, '\n')

    tcpsport = tcp.sport
    tcpdport = tcp.dport

    if tcpsport > highestport:
        highestport = tcpsport
    if tcpsport < lowestport:
        lowestport = tcpsport
    if tcpdport > highestport:
        highestport = tcpdport
    if tcpdport < lowestport:
        lowestport = tcpdport

    ts1 = ts
    
    print("Source Port: ", tcpsport, " Destination Port: ", tcpdport, " At Timestamp: ", datetime.fromtimestamp(ts), " For Duration: ", ts1-ts2, '\n')
    
    inc += 1
    ts2 = ts1
    print('\n')
    print("##########################################################\n")
    print("#", inc, " Scan\n")
    #print(ts, len(buf))

print('\n')
print("##########################################################\n")
print('\n')
print("Ethernet: ",  eth, '\n')

# for ts, buf in pcap:
#     eth = dpkt.ethernet.Ethernet(buf)


ip = eth.data
tcp = ip.data
tcpsport = tcp.sport
tcpdport = tcp.dport
datetime1 = datetime.fromtimestamp(firsttimestamp)
datetime2 = datetime.fromtimestamp(ts)

print("IP: ", ip, " TCP: ", tcp, " TCP SPort: ", tcpsport, " TCP DPort: ", tcpdport, '\n')
print("The ports span: ", lowestport, " to ", highestport, '\n')
print("There were ", inc, " scans taken \n")
print("The scans were taken between ", firsttimestamp, "and", ts, '\n')
print("The scans took ", ts - firsttimestamp, "seconds, or ", (ts-firsttimestamp)/60, " minutes \n")
print("The scans were taken between: ", datetime1, "and", datetime2, '\n')

