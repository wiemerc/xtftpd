#include <iostream>
#include <stdexcept>

#include "Poco/Format.h"
#include "Poco/Net/RawSocket.h"
#include "Poco/Net/SocketAddress.h"


static const int MAX_PACKET_SIZE = 1500;
static const int IP_HDR_SIZE     = 20;
static const int ICMP_HDR_SIZE   = 8;			// for an echo request


//
// calculate IP / ICMP checksum (taken from the code for in_cksum() floating on the net)
//
static uint16_t chksum (uint8_t * bytes, uint32_t len)
{
    uint32_t sum, i;
    uint16_t * p;

    sum = 0;
    p = (uint16_t *) bytes;

    for (i = len; i > 1; i -= 2)				// sum all 16-bit words
        sum += *p++;

    if (i == 1)									// add an odd byte if necessary
        sum += (uint16_t) *((uint8_t *) p);

	sum = (sum >> 16) + (sum & 0x0000ffff);		// fold in upper 16 bits
	sum += (sum >> 16);							// add carry bits
    return ~((uint16_t) sum);					// return 1-complement truncated to 16 bits
}


//
// class representing an IP packet
//
// TODO: additional options are not considered
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
		void calcChecksum()
		{
			// recalculate IP checksum (header only)
			m_checksum = 0;
			m_checksum = chksum ((uint8_t *) this, IP_HDR_SIZE);
		}


		const uint16_t length() const
		{
			return ntohs (m_length);
		}


		void setLength (const uint8_t length)
		{
			m_length = htons (length);
		}


		const uint8_t protocol() const
		{
			return m_protocol;
		}


		const std::string srcAddr() const
		{
			std::string addr;
			for (int8_t offset = 0; offset <= 24; offset += 8)
				addr += std::to_string ((m_srcAddr >> offset) & 0xff) + ".";

			addr.resize (addr.size() - 1);
			return addr;
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
		void calcChecksum (const uint16_t dataLen)
		{
			// recalculate ICMP checksum (header *and* data)
			m_checksum = 0;
			m_checksum = chksum ((uint8_t *) this, dataLen + ICMP_HDR_SIZE);
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
				std::cerr << "IP packet received from " << ip->srcAddr() << ":" << std::endl;
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
				std::cerr << "ICMP packet extracted" << std::endl;
			}
			else
			{
				std::cerr << "did not receive enough bytes for an ICMP packet" << std::endl;
				continue;
			}

			// extract payload, replace numbers with 'x' and add a string
			if (ip->length() > (IP_HDR_SIZE + ICMP_HDR_SIZE))
			{
				uint8_t *data = icmp->payload();
				int dataLen = ip->length() - (IP_HDR_SIZE + ICMP_HDR_SIZE);
				for (int i = dataLen - 8; i < dataLen; i++)
					data[i] = 'x';
				for (int i = dataLen; i < dataLen + 8; i++)
					data[i] = 'y';
				std::cerr << "changed payload" << std::endl;

				// re-inject packet into network stack
				icmp->calcChecksum (dataLen + 8);
				ip->setLength (ip->length() + 8);
				ip->calcChecksum();
				sock.sendTo (buffer, ip->length(), sender);
				std::cerr << "IP packet re-injected:" << std::endl;
				std::cerr << hexdump (buffer, 92) << std::endl;
			}
			else
			{
				std::cerr << "received an ICMP packet without payload" << std::endl;
				continue;
			}

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
