#!/usr/bin/env python
#Alden Shiverick 
#CS4349

import dpkt
import sys 
from datetime import datetime

try:
    file = open('test-2.pcap', 'rb')            #change "test-2.pcap" to the pcap file you want to test with, include location of the file if it is not in this folder
    pcap = dpkt.pcap.Reader(file)
    print("PCAP file opened and read \n")
except (IOError, KeyError):
    print("Could not open file!")               #if you recieve this error output in the console the file is not properly opening
    sys.exit(-1)                                #make sure file location is correct and there are not typos 

inc = 0
ts1 = 0
ts2 = 0
firsttimestamp = 0
lowestport = 1000000
highestport = 0
scanduration = 0
totaltime = 0
avtime = 0

for ts, buf in pcap:
    print("##########################################################\n")
    print("#", inc+1, " Scan\n")

    if inc == 0:
        firsttimestamp = ts
        ts2 = ts
    
    eth = dpkt.ethernet.Ethernet(buf)

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
    scanduration = ts1-ts2
    
    print("Source Port: ", tcpsport, " Destination Port: ", tcpdport, " At Timestamp: ", datetime.fromtimestamp(ts), " Duration of Scan: ", scanduration, '\n')
    
    inc += 1
    totaltime += scanduration
    ts2 = ts1
    print('\n')

print('\n')
print("##########################################################\n")
print('\n')

ip = eth.data
tcp = ip.data
tcpsport = tcp.sport
tcpdport = tcp.dport
datetime1 = datetime.fromtimestamp(firsttimestamp)
datetime2 = datetime.fromtimestamp(ts)
avtime = totaltime/inc

print("The ports span: ", lowestport, " to ", highestport, '\n')
print("There were ", inc, " scans taken \n")
print("The scans were taken between ", firsttimestamp, "and", ts, '\n')
print("The scans took ", ts - firsttimestamp, "seconds, or ", (ts-firsttimestamp)/60, " minutes \n")
print("The scans were taken between: ", datetime1, "and", datetime2, '\n')
print("Average time during scans: ", avtime, "seconds \n")
