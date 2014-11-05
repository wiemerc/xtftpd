#!/opt/local/bin/python2.7
#
# xtftp.py - proof-of concept for a TFTP program which uses ICMP packets as transport
#
# Copyright(C) 2013, 2014 Constantin Wiemer


import sys
import os
import struct
from scapy.all import IP, ICMP
import socket


# opcodes
OP_RRQ   = 1
OP_DATA  = 3
OP_ACK   = 4
OP_ERROR = 5

# states
S_SENDING = 1
S_WAITING = 2

MAX_PACKET_SIZE = 1500
IP_HDR_LEN      = 20
ICMP_HDR_LEN    = 8


cookie = os.getpid()
seq    = 0
state  = S_SENDING
data   = ''

s = socket.socket (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

while True:
    seq += 1

    if state == S_SENDING:
        # send read request
        pkt = struct.pack ('!H', cookie) + struct.pack ('!H', OP_RRQ) + sys.argv[2] + '\x00netascii\x00'
        pkt = ICMP (id = cookie, seq = seq) / pkt 
        state = S_WAITING

    elif state == S_WAITING:
        # answer is a data packet => store data and acknowledge it until
        print "cookie =", struct.unpack ('!H', ans[0:2]) [0]
        if cookie != struct.unpack ('!H', ans[0:2]) [0]:
            print "incorrect cookie received:", struct.unpack ('!H', ans[0:2]) [0]
            break

        opcode = struct.unpack ('!H', ans[2:4]) [0]
        print "opcode =", opcode

        if opcode == OP_DATA:
            blknum = struct.unpack ('!H', ans[4:6]) [0]
            print "blknum =", blknum
            data += ans[6:]

            pkt = struct.pack ('!H', cookie) + struct.pack ('!H', OP_ACK) + struct.pack ('!H', blknum)
            pkt = IP (dst = sys.argv[1]) / ICMP (id = cookie, seq = seq) / pkt

        elif opcode == OP_ERROR:
            print "received error:", ans[4:-1]
            break

        elif opcode == OP_ACK:
            print "acknowledgement received => received all data"
            break

        else:
            print "received invalid opcode:", opcode
            break

    s.sendto (str (pkt), 0, (sys.argv[1], 0))
    ans = s.recvfrom (MAX_PACKET_SIZE) [0][IP_HDR_LEN:]
    # We loop until we receive an ICMP echo reply packet because through the raw socket we receive *all* ICMP packets
    while ord (ans[0]) != 0:
        ans = s.recvfrom (MAX_PACKET_SIZE) [0][IP_HDR_LEN:]
    ans = ans[ICMP_HDR_LEN:]

print "data received:"
print data

