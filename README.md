# xtftpd - TFTP daemon that uses ICMP as transport protocol

Copyright(C) 2013, 2014, 2017 Constantin Wiemer

xtftp is a proof-of-concept for a TFTP server (see RFC 1350 (http://tools.ietf.org/html/rfc1350) for details) which uses ICMP packets as transport in order to disguise the communication. It is written in C++ and uses FreeBSD divert socket to process packets in userspace and (a slightly patched version of) the Poco libraries (http://pocoproject.org/index.html). I wrote it for educational purposes and fun, so only part of the TFTP protocol is implemented and the server is not particularly robust and will contain bugs for sure. There is also a small accompanying Python program that can act as client.
