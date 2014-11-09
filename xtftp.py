#!/opt/local/bin/python2.7
#
# xtftp.py - client for the TFTP server with ICMP packets as transport
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


cookie = os.getpid() % 65536
seq    = 0
state  = S_SENDING
data   = ''

s = socket.socket (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

while True:
    seq += 1

    if state == S_SENDING:
        # send read request
        print "sending request for file '%s'..." % sys.argv[2]
        pkt = struct.pack ('!H', cookie) + struct.pack ('!H', OP_RRQ) + sys.argv[2] + '\x00netascii\x00'
        pkt = ICMP (id = cookie, seq = seq) / pkt 
        state = S_WAITING

    elif state == S_WAITING:
		# process answer
        print "cookie =", struct.unpack ('!H', ans[0:2]) [0]
        if cookie != struct.unpack ('!H', ans[0:2]) [0]:
            print "incorrect cookie received:", struct.unpack ('!H', ans[0:2]) [0]
            break

        opcode = struct.unpack ('!H', ans[2:4]) [0]
        print "opcode =", opcode

        if opcode == OP_DATA:
			# answer is a data packet => store data and acknowledge it
            blknum = struct.unpack ('!H', ans[4:6]) [0]
            print "data packet received, blknum =", blknum
            data += ans[6:]

            pkt = struct.pack ('!H', cookie) + struct.pack ('!H', OP_ACK) + struct.pack ('!H', blknum)
            pkt = ICMP (id = cookie, seq = seq) / pkt

        elif opcode == OP_ERROR:
			# answer is an error => terminate
            print "received error:", ans[4:-1]
            break

        elif opcode == OP_ACK:
			# answer is the acknowledgement we sent => terminate
            print "acknowledgement received => received all data"
            break

        else:
            print "received invalid opcode:", opcode
            break


	# send packet out
    s.sendto (str (pkt), 0, (sys.argv[1], 0))

    # loop until we receive an ICMP echo reply packet, because of the raw socket we receive *all* ICMP packets
    ans = s.recvfrom (MAX_PACKET_SIZE) [0][IP_HDR_LEN:]
    while ord (ans[0]) != 0:
        ans = s.recvfrom (MAX_PACKET_SIZE) [0][IP_HDR_LEN:]
    ans = ans[ICMP_HDR_LEN:]
    print
    print "answer received"


print
print "data received:"
print data
