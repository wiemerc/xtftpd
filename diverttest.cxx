#include <iostream>
#include <stdexcept>
#include <c++/v1/exception>

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
        typedef struct 
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
        } IPHeader;

        IPHeader *m_header;
		uint8_t  *m_data;
        uint16_t  m_length;

	public:
        IPPacket (uint8_t *buffer, uint16_t length)
        {
            if (length > sizeof (IPHeader))
            {
                m_header = (IPHeader *) buffer;
                m_data   = buffer + sizeof (IPHeader);
                m_length = length - sizeof (IPHeader);
            }
            else
                throw std::runtime_error ("not enough bytes for IP packet");
        }

		void calcChecksum()
		{
			// recalculate IP checksum (header only)
			m_header->m_checksum = 0;
			m_header->m_checksum = chksum ((uint8_t *) m_header, sizeof (IPHeader));
		}


		const uint16_t payloadLen() const
		{
			return m_length;
		}


		void setPayloadLen (const uint16_t length)
		{
            m_length = length;
			m_header->m_length = htons (length + sizeof (IPHeader));
		}


		const uint8_t protocol() const
		{
			return m_header->m_protocol;
		}


		const std::string srcAddr() const
		{
			std::string addr;
			for (int8_t offset = 0; offset <= 24; offset += 8)
				addr += std::to_string ((m_header->m_srcAddr >> offset) & 0xff) + ".";

			addr.resize (addr.size() - 1);		// remove the last dot
			return addr;
		}


		uint8_t *payload()
		{
			return m_data;
		}
};


//
// class representing an ICMP echo request packet
//
class ICMPEchoRequest
{
        typedef struct
        {
            uint8_t  m_type;
            uint8_t  m_code;
            uint16_t m_checksum;
            uint16_t m_id;
            uint16_t m_seqnum;
//            uint16_t m_cookie;
        } ICMPEchoHeader;

        ICMPEchoHeader *m_header;
		uint8_t        *m_data;
        uint16_t        m_length;

	public:
        ICMPEchoRequest (uint8_t *buffer, uint16_t length)
        {
            if (length > sizeof (ICMPEchoHeader))
            {
                m_header = (ICMPEchoHeader *) buffer;
                m_data   = buffer + sizeof (ICMPEchoHeader);
                m_length = length - sizeof (ICMPEchoHeader);
            }
            else
                throw std::runtime_error ("not enough bytes for ICMP echo request");
        }

		void calcChecksum()
		{
			// recalculate ICMP checksum (header *and* data)
			m_header->m_checksum = 0;
			m_header->m_checksum = chksum ((uint8_t *) m_header, sizeof (ICMPEchoHeader) + m_length);
		}


		const uint16_t payloadLen() const
		{
			return m_length;
		}


		void setPayloadLen (const uint16_t length)
		{
            m_length = length;
		}


		uint8_t *payload()
		{
			return m_data;
		}
};


std::string hexdump (const uint8_t *buffer, size_t length)
{
    std::string dump;
    size_t pos = 0;

    while (pos < length)
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
        if (line.size() < 16)
            dump.append (3 * (16 - line.size()), ' ');

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
		// TODO: check if buffer is large enough
		while (true)
		{
			// receive diverted IP packet from network stack (+ ICMP + payload)
			IPPacket ip (buffer, sock.receiveFrom (buffer, MAX_PACKET_SIZE, sender));
            std::cerr << "IP packet received from " << ip.srcAddr() << ":" << std::endl;
            std::cerr << hexdump (buffer, 84) << std::endl;

			// extract ICMP packet (we assume we only get ICMP echo requests)
			if (ip.protocol() != IPPROTO_ICMP)
			{
				std::cerr << "IP packet does not contain an ICMP packet" << std::endl;
				break;
			}
			ICMPEchoRequest icmp (ip.payload(), ip.payloadLen());	
			std::cerr << "ICMP packet extracted" << std::endl;

			// extract payload, replace numbers with 'x' and add a string
            // TODO: create TFTP packet and send it as payload
			if (icmp.payloadLen() > 0)
			{
				uint8_t *data = icmp.payload();
				uint16_t len  = icmp.payloadLen();
				for (int i = len - 8; i < len; i++)
					data[i] = 'x';
				for (int i = len; i < len + 8; i++)
					data[i] = 'y';
				std::cerr << "changed payload" << std::endl;

				// re-inject packet into network stack
				icmp.setPayloadLen (len + 8);
				icmp.calcChecksum();
				ip.setPayloadLen (ip.payloadLen() + 8);
				ip.calcChecksum();
				sock.sendTo (buffer, ip.payloadLen() + IP_HDR_SIZE, sender);
				std::cerr << "IP packet re-injected:" << std::endl;
				std::cerr << hexdump (buffer, 92) << std::endl;
			}
			else
			{
				std::cerr << "received an ICMP packet without payload" << std::endl;
				continue;
			}

		}
		sock.close();
	}
    catch (std::exception &e)
    {
        std::cerr << "exception occurred: " << e.what() << std::endl;
		return 1;
    }
    return 0;
}
