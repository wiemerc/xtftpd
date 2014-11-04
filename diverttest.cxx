#include <iostream>
#include <stdexcept>
#include <cstring>

#include "Poco/Format.h"
#include "Poco/Net/RawSocket.h"
#include "Poco/Net/SocketAddress.h"


static const int MAX_PACKET_SIZE      = 1500;
static const int MAX_TFTP_PACKET_SIZE = 512;
static const int IP_HDR_SIZE          = 20;
static const int ICMP_HDR_SIZE        = 8;			// for an echo request


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
// class representing a memory buffer (for packets and payloads)
//
class Buffer
{
public:
	uint8_t *m_addr;
	uint16_t m_size;


	Buffer (uint8_t *addr, const uint16_t size) : m_addr (addr), m_size (size)
	{
	}
};



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
		Buffer    m_payload;

	public:
        IPPacket (const Buffer &buffer) :
			m_payload (buffer.m_addr + sizeof (IPHeader), buffer.m_size - sizeof (IPHeader))
        {
            if (buffer.m_size > sizeof (IPHeader))
            {
                m_header = (IPHeader *) buffer.m_addr;
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


		Buffer packet()
		{
			return Buffer ((uint8_t *) m_header, sizeof (IPHeader) + m_payload.m_size);
		}


		Buffer payload()
		{
			return m_payload;
		}


		void setPayload (const Buffer &buffer)
		{
			// We assume here that a buffer of size MAX_PACKET_SIZE has been allocated for us
			if (buffer.m_size > (MAX_PACKET_SIZE - IP_HDR_SIZE))
				throw std::runtime_error ("payload exceeds maximum size");
			else
			{
				// If the new payload resides at a different memory location, we need to copy it
				if (buffer.m_addr != m_payload.m_addr)
					memcpy (m_payload.m_addr, buffer.m_addr, buffer.m_size);
				m_payload.m_size     = buffer.m_size;
				m_header->m_length = htons (buffer.m_size + IP_HDR_SIZE);
			}
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
        } ICMPEchoHeader;

        ICMPEchoHeader *m_header;
		Buffer			m_payload;

	public:
        ICMPEchoRequest (const Buffer &buffer) :
			m_payload (buffer.m_addr + sizeof (ICMPEchoHeader), buffer.m_size - sizeof (ICMPEchoHeader))
        {
            if (buffer.m_size > sizeof (ICMPEchoHeader))
            {
                m_header = (ICMPEchoHeader *) buffer.m_addr;
            }
            else
                throw std::runtime_error ("not enough bytes for ICMP echo request");
        }

		void calcChecksum()
		{
			// recalculate ICMP checksum (header *and* data)
			m_header->m_checksum = 0;
			m_header->m_checksum = chksum ((uint8_t *) m_header, sizeof (ICMPEchoHeader) + m_payload.m_size);
		}


		Buffer packet()
		{
			return Buffer ((uint8_t *) m_header, sizeof (ICMPEchoHeader) + m_payload.m_size);
		}


		Buffer payload()
		{
			return m_payload;
		}


		void setPayload (const Buffer &buffer)
		{
			// We assume here that a buffer of size MAX_PACKET_SIZE has been allocated for us
			if (buffer.m_size > (MAX_PACKET_SIZE - IP_HDR_SIZE - ICMP_HDR_SIZE))
				throw std::runtime_error ("payload exceeds maximum size");
			else
			{
				// If the new payload resides at a different memory location, we need to copy it
				if (buffer.m_addr != m_payload.m_addr)
					memcpy (m_payload.m_addr, buffer.m_addr, buffer.m_size);
				m_payload.m_size = buffer.m_size;
			}
		}
};



//
// class representing a TFTP packet
//
class TFTPPacket
{
protected:
	typedef struct
	{
		uint16_t m_cookie;				// an extension to the RFC
		uint16_t m_opcode;
	} TFTPHeader;

	TFTPHeader *m_header;

public:
	// construct object from a buffer
	TFTPPacket (const Buffer &buffer)
	{
		if (buffer.m_size >= sizeof (TFTPHeader))
		{
			m_header = (TFTPHeader *) buffer.m_addr;
		}
		else
			throw std::runtime_error ("not enough bytes for TFTP packet");
	}


	// construct object in the specified buffer from parameters
	TFTPPacket (const Buffer &buffer, const uint16_t cookie, const uint16_t opcode)
	{
		if (sizeof (TFTPHeader) > (MAX_PACKET_SIZE - IP_HDR_SIZE - ICMP_HDR_SIZE))
			throw std::runtime_error ("buffer not large enough for TFTP packet");

		m_header = (TFTPHeader *) buffer.m_addr;
		m_header->m_cookie = htons (cookie);
		m_header->m_opcode = htons (opcode);
	}


	const uint16_t cookie() const
	{
		return ntohs (m_header->m_cookie);
	}


	const uint16_t opcode() const
	{
		return ntohs (m_header->m_opcode);
	}
};



class TFTPReqPacket : public TFTPPacket
{
	char    *m_data;				// contains both the file name and the mode as null-terminated strings
	uint16_t m_size;

    public:
        // construct object from a buffer
        TFTPReqPacket (const Buffer &buffer) : TFTPPacket (buffer)
        {
            if (buffer.m_size > sizeof (TFTPHeader))
            {
                m_data = (char *) buffer.m_addr + sizeof (TFTPHeader);
            }
            else
                throw std::runtime_error ("not enough bytes for TFTP request packet");
        }


        // construct object in the specified buffer from parameters
        TFTPReqPacket (const Buffer &buffer, const uint16_t cookie, const uint16_t opcode, const char * fname) :
			TFTPPacket (buffer, cookie, opcode)
        {
			m_size = strlen (fname) + strlen ("netascii") + 2;	// + 2 accounts for the two terminating null bytes
			if ((m_size + sizeof (TFTPHeader)) > MAX_TFTP_PACKET_SIZE)
				throw std::runtime_error ("size of TFTP request packet exceeds maximum size for a TFTP packet");
            if ((m_size + sizeof (TFTPHeader)) > (MAX_PACKET_SIZE - IP_HDR_SIZE - ICMP_HDR_SIZE))
                throw std::runtime_error ("buffer not large enough for TFTP request packet");
            
			m_data = (char *) buffer.m_addr + sizeof (TFTPHeader);
			strcpy (m_data, fname);
			strcpy (m_data + strlen (fname) + 1, "netascii");
        }


		Buffer packet()
		{
			return Buffer ((uint8_t *) m_header, sizeof (TFTPHeader) + m_size);
		}


		const char *fname() const
		{
			// TODO: check if string is actually null-terminated
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
        for (size_t i = pos; (i < pos + 16) && (i < length); i++)
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
		Buffer					 packet (buffer, MAX_PACKET_SIZE);

		sock.bind (Poco::Net::SocketAddress (argv[1]));
		while (true)
		{
			std::cerr << "waiting for packets..." << std::endl;

			// receive diverted IP packet from network stack (+ ICMP + payload)
			packet.m_size = sock.receiveFrom (packet.m_addr, packet.m_size, sender);
			IPPacket ip (packet);
            std::cerr << "IP packet received from " << ip.srcAddr() << ":" << std::endl;
            std::cerr << hexdump (ip.packet().m_addr, ip.packet().m_size) << std::endl;

			// extract ICMP packet (we assume we only get ICMP echo requests)
			if (ip.protocol() != IPPROTO_ICMP)
			{
				std::cerr << "IP packet does not contain an ICMP packet" << std::endl;
				break;
			}
			ICMPEchoRequest icmp (ip.payload());
			std::cerr << "ICMP packet extracted" << std::endl;

			// replace payload with an TFTP request packet
			TFTPReqPacket req (icmp.payload(), 4711, 1, "/etc/hosts");
			icmp.setPayload (req.packet());
			icmp.calcChecksum();
			std::cerr << "changed payload" << std::endl;

			// re-inject packet into network stack
			ip.setPayload (icmp.packet());
			ip.calcChecksum();
			sock.sendTo (ip.packet().m_addr, ip.packet().m_size, sender);
			std::cerr << "IP packet re-injected:" << std::endl;
			std::cerr << hexdump (ip.packet().m_addr, ip.packet().m_size) << std::endl;
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
