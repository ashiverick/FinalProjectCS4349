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

for ts, buf in pcap:

    eth = dpkt.ethernet.Ethernet(buf)

    ip = eth.data
    print("IP Data: ", ip, '\n')
    tcp = ip.data
    print("TCP Data: ", tcp, '\n')
    tcpsport = tcp.sport
    tcpdport = tcp.dport

    print("Source Port: ", tcpsport, " Destination Port: ", tcpdport, " At Timestamp: ", datetime.fromtimestamp(ts), '\n')
    inc = inc + 1
    print(ts, len(buf))
print('\n')
print("Ethernet: ",  eth, '\n')

# for ts, buf in pcap:
#     eth = dpkt.ethernet.Ethernet(buf)


ip = eth.data
tcp = ip.data
tcpsport = tcp.sport
tcpdport = tcp.dport

datetime = datetime.fromtimestamp(ts)

print("IP: ", ip, " TCP: ", tcp, " TCP SPort: ", tcpsport, " TCP DPort: ", tcpdport, '\n')
print("The ports span: ", tcpsport, " to ", tcpdport, '\n')
print("There are ", tcpsport-tcpdport, " ports total. \n")
print("The scans were taken at ", ts, '\n')
print("The scans were taken at datetime: ", datetime, '\n')

