#include <iostream>
#include <stdexcept>

#include "Poco/Net/RawSocket.h"
#include "Poco/Net/SocketAddress.h"


static const int MAX_PACKET_SIZE = 1024;
static const int IP_HDR_SIZE     = 20;


//
// class representing an IP packet
//
class IPPacket
{
		uint8_t  m_versionIHL;		// 4 bits version and 4 bits internet header length
		uint8_t  m_TOS;
		uint16_t m_length;
		uint16_t m_id;
		uint16_t m_flagsOffset;		// 3 bits flags and 13 bits fragment offset
		uint8_t  m_TTL;
		uint8_t  m_protocol;
		uint16_t m_checksum;
		uint32_t m_srcAddr;
		uint32_t m_dstAddr;

		uint8_t *m_payload;

	public:
		void fromBuffer(uint8_t *bytes, int nbytes)
		{
			// copy the bytes that make up the header to our position in memory so that all members get initialized,
			// then do the conversion from network to host byte order
			// TODO: additional options are not considered
			if (nbytes >= IP_HDR_SIZE)
			{
				memcpy (this, bytes, IP_HDR_SIZE);
				m_length      = ntohs (m_length);
				m_id          = ntohs (m_id);
				m_flagsOffset = ntohs (m_flagsOffset);
				m_checksum    = ntohs (m_checksum);
				m_srcAddr     = ntohl (m_srcAddr);
				m_dstAddr     = ntohl (m_dstAddr);
			}
			else
				throw std::runtime_error ("not enough bytes to create IP header");

			// just store a pointer to the remaining bytes = payload
			if (nbytes == m_length)
				if (nbytes > IP_HDR_SIZE)
					m_payload = bytes + IP_HDR_SIZE;
				else
					m_payload = NULL;
			else
				throw std::runtime_error ("number of bytes not equal to length in IP header");
		}
};


//
// class representing an ICMP packet
//
class ICMPPacket
{
};


//
// calculate IP / ICMP checksum
//
static unsigned short chksum (unsigned char * bytes, unsigned int len)
{
    unsigned int sum, i;
    unsigned short * p;

    sum = 0;
    p = (unsigned short *) bytes;

    for (i = len; i > 1; i -= 2)
        sum += *p++;

    if (i == 1)
        sum += (unsigned short) *((unsigned char *) p);

    while (sum & 0xffff0000)
        sum = (sum >> 16) + (sum & 0x0000ffff);

    return ~((unsigned short) sum);
}


int main (int argc, char ** argv)
{
	try
	{
		// The inclHeader flag (3rd parameter below) is only available in the patched version of Poco
		Poco::Net::RawSocket     sock (Poco::Net::IPAddress::IPv4, IPPROTO_DIVERT, false);
		Poco::Net::SocketAddress sender;
		unsigned char            buffer[MAX_PACKET_SIZE];

		sock.bind (Poco::Net::SocketAddress (argv[1]));
		std::cerr << "waiting for packets..." << std::endl;
		while (true)
		{
			// receive diverted packet from network stack (IP + ICMP + payload)
			int n = sock.receiveFrom (buffer, MAX_PACKET_SIZE, sender);
			std::cerr << "packet received" << std::endl;

			// replace numbers in payload with 'x'
			for (int i = n - 8; i < n; i++)
				buffer[i] = 'x';

			// recalculate ICMP checksum (header *and* data)
			*((short *) (buffer + IP_HDR_SIZE + 2)) = 0;
			*((short *) (buffer + IP_HDR_SIZE + 2)) = chksum (buffer + IP_HDR_SIZE, n - IP_HDR_SIZE);

			// recalculate IP checksum (header only)
			*((short *) (buffer + 10)) = 0;
			*((short *) (buffer + 10)) = chksum (buffer, IP_HDR_SIZE);

			// re-inject packet into network stack
			sock.sendTo (buffer, n, sender);
			std::cerr << "packet re-injected" << std::endl;
		}
		sock.close();
	}
    catch (Poco::Exception &e)
    {
        std::cerr << "exception occurred: " << e.what() << std::endl;
		return 1;
    }
    return 0;
}
