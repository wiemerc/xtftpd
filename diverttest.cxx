#include <iostream>
#include <stdexcept>

#include "Poco/Format.h"
#include "Poco/Net/RawSocket.h"
#include "Poco/Net/SocketAddress.h"


static const int MAX_PACKET_SIZE = 1500;
static const int IP_HDR_SIZE     = 20;
static const int ICMP_HDR_SIZE   = 8;			// for an echo request


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


//
// class representing an IP packet
//
// TODO: additional options are not considered
// TODO: change byte order only in getter methods
class IPPacket
{
		uint8_t  m_versionIHL;					// 4 bits version and 4 bits internet header length
		uint8_t  m_TOS;
		uint16_t m_length;
		uint16_t m_id;
		uint16_t m_flagsOffset;					// 3 bits flags and 13 bits fragment offset
		uint8_t  m_TTL;
		uint8_t  m_protocol;
		uint16_t m_checksum;
		uint32_t m_srcAddr;
		uint32_t m_dstAddr;

		// The payload probably needs to be aligned on a word boundary so we can create an object
		// out of it. This is the case here because the standard IP header is 20 bytes long.
		uint8_t m_payload[MAX_PACKET_SIZE - IP_HDR_SIZE];

	public:
		void netToHost()
		{
			// change byte order
			m_length      = ntohs (m_length);
			m_id          = ntohs (m_id);
			m_flagsOffset = ntohs (m_flagsOffset);
			m_checksum    = ntohs (m_checksum);
			m_srcAddr     = ntohl (m_srcAddr);
			m_dstAddr     = ntohl (m_dstAddr);
		}


		void hostToNet()
		{
			// change byte order
			m_length      = htons (m_length);
			m_id          = htons (m_id);
			m_flagsOffset = htons (m_flagsOffset);
			m_checksum    = htons (m_checksum);
			m_srcAddr     = htonl (m_srcAddr);
			m_dstAddr     = htonl (m_dstAddr);

			// recalculate IP checksum (header only)
			m_checksum = 0;
			m_checksum = chksum ((uint8_t *) this, IP_HDR_SIZE);
		}


		const uint16_t length() const
		{
			return m_length;
		}


		const uint8_t protocol() const
		{
			return m_protocol;
		}


		uint8_t *payload()
		{
			return m_payload;
		}
};


//
// class representing an ICMP echo request packet
//
class ICMPEchoRequest
{
		uint8_t  m_type;
		uint8_t  m_code;
		uint16_t m_checksum;
		uint16_t m_id;
		uint16_t m_seqnum;

		uint8_t m_payload[MAX_PACKET_SIZE - IP_HDR_SIZE - ICMP_HDR_SIZE];

	public:
		void netToHost()
		{
			// change byte order
			m_checksum    = ntohs (m_checksum);
			m_id          = ntohs (m_id);
			m_seqnum      = ntohs (m_seqnum);
		}


		void hostToNet (const uint16_t length)
		{
			m_checksum    = htons (m_checksum);
			m_id          = htons (m_id);
			m_seqnum      = htons (m_seqnum);

			// recalculate ICMP checksum (header *and* data), length is the total length of the IP packet,
			// so we need to subtract the length of the IP header
			m_checksum = 0;
			m_checksum = chksum ((uint8_t *) this, length - IP_HDR_SIZE);
		}


		uint8_t *payload()
		{
			return m_payload;
		}
};


std::string hexdump (const uint8_t *buffer, size_t size)
{
    std::string dump;
    size_t pos = 0;

    while (pos < size)
    {
        dump += Poco::format ("%04?x: ", pos);
        std::string line;
        for (size_t i = pos; i < pos + 16; i++)
        {
            dump += Poco::format ("%02?x ", buffer[i]);
            if (buffer[i] >= 0x20 && buffer[i] <= 0x7e)
            {
                line.append (1, buffer[i]);
            }
            else
            {
                line.append (1, '.');
            }
        }
        if (line.length() < 16)
            dump.append (3 * (16 - line.length()), ' ');

        dump.append (1, '\t');
        dump += line;
        dump.append (1, '\n');
        pos += 16;
    }
    return dump;
}


int main (int argc, char ** argv)
{
	try
	{
		// The inclHeader flag (3rd parameter below) is only available in the patched version of the Poco libraries
		Poco::Net::RawSocket     sock (Poco::Net::IPAddress::IPv4, IPPROTO_DIVERT, false);
		Poco::Net::SocketAddress sender;
		uint8_t					 buffer[MAX_PACKET_SIZE];

		sock.bind (Poco::Net::SocketAddress (argv[1]));
		std::cerr << "waiting for packets..." << std::endl;
		// TODO: loop never terminates
		while (true)
		{
			// receive diverted IP packet from network stack (+ ICMP + payload)
			IPPacket *ip;	
			if (sock.receiveFrom (buffer, MAX_PACKET_SIZE, sender) >= IP_HDR_SIZE)
			{
				ip = new (buffer) IPPacket;
				ip->netToHost();
				std::cerr << "IP packet received:" << std::endl;
				std::cerr << hexdump (buffer, 84) << std::endl;
			}
			else
			{
				std::cerr << "did not receive enough bytes for an IP packet" << std::endl;
				continue;
			}

			// extract ICMP packet (we assume we only get ICMP echo requests)
			ICMPEchoRequest *icmp;	
			if ((ip->protocol() == IPPROTO_ICMP) && (ip->length() >= (IP_HDR_SIZE + ICMP_HDR_SIZE)))
			{
				icmp = new (ip->payload()) ICMPEchoRequest;
				icmp->netToHost();
				std::cerr << "ICMP packet extracted" << std::endl;
			}
			else
			{
				std::cerr << "did not receive enough bytes for an ICMP packet" << std::endl;
				continue;
			}

			// extract payload and replace numbers with 'x'
			if (ip->length() > (IP_HDR_SIZE + ICMP_HDR_SIZE))
			{
				uint8_t *data = icmp->payload();
				int n = ip->length() - (IP_HDR_SIZE + ICMP_HDR_SIZE);
				for (int i = n - 8; i < n; i++)
					data[i] = 'x';
				std::cerr << "changed payload" << std::endl;
			}
			else
			{
				std::cerr << "received an ICMP packet without payload" << std::endl;
				continue;
			}

			// re-inject packet into network stack
			icmp->hostToNet (ip->length());
			std::cerr << "IP packet re-injected:" << std::endl;
			std::cerr << hexdump (buffer, 84) << std::endl;
			ip->hostToNet();
			sock.sendTo (buffer, ntohs (ip->length()), sender);
		}
		// Normally we would have to call the dtors of the packet objects *explicitly* because of the placement new operator,
		// but as they reside in the buffer allocated on the stack, there is actually nothing to destroy.
		sock.close();
	}
    catch (Poco::Exception &e)
    {
        std::cerr << "exception occurred: " << e.what() << std::endl;
		return 1;
    }
    return 0;
}
