//
// Proof-of-concept for a TFTP server (see RFC 1350 (http://tools.ietf.org/html/rfc1350) for details) which uses ICMP packets as transport
// It uses FreeBSD divert socket to process packets in userspace and the Poco libraries (http://pocoproject.org/index.html).
//
// Copyright(C) 2013, 2014 Constantin Wiemer
//



//
// header files
//
#include <fstream>
#include <stdexcept>
#include <vector>
#include <string>

#include "log4cxx/logger.h"
#include "log4cxx/propertyconfigurator.h"

#include "Poco/Util/ServerApplication.h"
#include "Poco/Util/IntValidator.h"
#include "Poco/Logger.h"
#include "Poco/Format.h"
#include "Poco/Net/RawSocket.h"
#include "Poco/Net/SocketAddress.h"



//
// constants
//
static const int MAX_PACKET_SIZE      = 1024;
static const int MAX_TFTP_PACKET_SIZE = 512;
static const int IP_HDR_SIZE          = 20;			// without additional options
static const int ICMP_HDR_SIZE        = 8;			// for an echo request

// opcodes
static const uint16_t OP_RRQ	 = 1;
static const uint16_t OP_DATA	 = 3;
static const uint16_t OP_ACK	 = 4;
static const uint16_t OP_ERROR  = 5;

// states
static const int S_IDLE         = 0;
static const int S_READY        = 1;
static const int S_WAIT_FOR_ACK = 2;

static const char *states[] = 
{
	"S_IDLE",
	"S_READY",
	"S_WAIT_FOR_ACK",
};

// error codes
static const uint16_t E_UNDEF          = 0;
static const uint16_t E_ILLEGAL_OPCODE = 4;



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
// generate a hexdump from a buffer of bytes
//
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
// class representing an IP packet (without additional options)
//
class IPPacket
{
	typedef struct 
	{
		uint8_t  m_versionIHL;				// 4 bits version and 4 bits header length
		uint8_t  m_TOS;
		uint16_t m_length;
		uint16_t m_id;
		uint16_t m_flagsOffset;				// 3 bits flags and 13 bits fragment offset
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


	const Buffer packet() const
	{
		return Buffer ((uint8_t *) m_header, sizeof (IPHeader) + m_payload.m_size);
	}


	const Buffer payload() const
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

		// recalculate IP checksum (header only)
		m_header->m_checksum = 0;
		m_header->m_checksum = chksum ((uint8_t *) m_header, sizeof (IPHeader));
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


	const Buffer packet() const
	{
		return Buffer ((uint8_t *) m_header, sizeof (ICMPEchoHeader) + m_payload.m_size);
	}


	const Buffer payload() const
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

		// recalculate ICMP checksum (header *and* data)
		m_header->m_checksum = 0;
		m_header->m_checksum = chksum ((uint8_t *) m_header, sizeof (ICMPEchoHeader) + m_payload.m_size);
	}
};



//
// classes representing a TFTP packet, different classes for different opcodes = different types of packets
//
namespace TFTP
{
	class Packet
	{
	protected:
		typedef struct
		{
			uint16_t m_cookie;				// an extension to the RFC
			uint16_t m_opcode;
		} Header;

		Header *m_header;

	public:
		Packet()
		{
		}


		// construct object from a buffer
		Packet (const Buffer &buffer)
		{
			if (buffer.m_size >= sizeof (Header))
			{
				m_header = (Header *) buffer.m_addr;
			}
			else
				throw std::runtime_error ("not enough bytes for a TFTP packet");
		}


		// construct object in the specified buffer from parameters
		Packet (const Buffer &buffer, const uint16_t cookie, const uint16_t opcode)
		{
			if (sizeof (Header) > (MAX_PACKET_SIZE - IP_HDR_SIZE - ICMP_HDR_SIZE))
				throw std::runtime_error ("buffer not large enough for TFTP packet");

			m_header = (Header *) buffer.m_addr;
			m_header->m_cookie = htons (cookie);
			m_header->m_opcode = htons (opcode);
		}


		virtual const Buffer packet() const
		{
			return Buffer ((uint8_t *) m_header, sizeof (Header));
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



	class ReqPacket : public Packet
	{
		char    *m_data;			// contains both the file name and the mode as null-terminated strings

    public:
        ReqPacket (const Buffer &buffer) : Packet (buffer)
        {
            if (buffer.m_size > sizeof (Header))
            {
                m_data = (char *) (buffer.m_addr + sizeof (Header));
            }
            else
                throw std::runtime_error ("not enough bytes for TFTP request packet");
        }


        const char *fname() const
        {
            // TODO: We should check if string is actually null-terminated
            return m_data;
        }
	};



	class DataPacket : public Packet
	{
		typedef struct
		{
			uint16_t m_blknum;
			uint8_t  m_bytes[];
		} PacketData;

		PacketData *m_data;
		uint16_t    m_size;

	public:
		DataPacket (const Buffer &buffer, const uint16_t cookie, const uint16_t blknum, const std::vector <uint8_t> &data) :
			Packet (buffer, cookie, OP_DATA)
		{
			if ((sizeof (Header) + sizeof (PacketData) + data.size()) > (MAX_PACKET_SIZE - IP_HDR_SIZE - ICMP_HDR_SIZE))
				throw std::runtime_error ("buffer not large enough for TFTP data packet");
			
			m_data = (PacketData *) (buffer.m_addr + sizeof (Header));
			m_data->m_blknum = htons (blknum);
			memcpy (m_data->m_bytes, data.data(), data.size());
			m_size = data.size() + 2;
		}


		virtual const Buffer packet() const
		{
			return Buffer ((uint8_t *) m_header, sizeof (Header) + m_size);
		}
	};



	class AckPacket : public Packet
	{
		uint16_t *m_blknum;

	public:
		AckPacket (const Buffer &buffer) : Packet (buffer)
		{
			if (buffer.m_size > sizeof (Header))
			{
				m_blknum = (uint16_t *) (buffer.m_addr + sizeof (Header));
			}
			else
				throw std::runtime_error ("not enough bytes for TFTP acknowledgment packet");
		}


		const uint16_t blknum() const
		{
			return ntohs (*m_blknum);
		}
	};



	class ErrorPacket : public Packet
	{
		typedef struct
		{
			uint16_t m_errcode;
			uint8_t  m_errmsg[];
		} PacketData;

		PacketData *m_data;
		uint16_t    m_size;

	public:
		ErrorPacket (const Buffer &buffer, const uint16_t cookie, const uint16_t errcode, const char *errmsg) :
			Packet (buffer, cookie, OP_ERROR)
		{
			if ((sizeof (Header) + sizeof (PacketData) + strlen (errmsg) + 1) > (MAX_PACKET_SIZE - IP_HDR_SIZE - ICMP_HDR_SIZE))
				throw std::runtime_error ("buffer not large enough for TFTP error packet");
			
			m_data = (PacketData *) (buffer.m_addr + sizeof (Header));
			m_data->m_errcode = htons (errcode);
			strcpy ((char *) m_data->m_errmsg, errmsg);
			m_size = strlen (errmsg) + 3;
		}


		virtual const Buffer packet() const
		{
			return Buffer ((uint8_t *) m_header, sizeof (Header) + m_size);
		}
	};
};  // namespace TFTP



//
// class that implements all the server functionality
//
class TFTPServer : public Poco::Util::ServerApplication 
{
    log4cxx::LoggerPtr logger;
	Buffer buffer;

public:
	TFTPServer() : logger (log4cxx::Logger::getLogger ("tftpd")),
                   buffer (new uint8_t[MAX_PACKET_SIZE], MAX_PACKET_SIZE)
	{
		log4cxx::PropertyConfigurator::configure ("logging.properties");
	}


	void initialize (Poco::Util::Application &self)
	{
		loadConfiguration();
		Poco::Util::Application::initialize (self);
	}


	int main (const std::vector<std::string> &args)
	{
		LOG4CXX_INFO (logger, "server has started up");

		try
		{
			// The inclHeader flag (3rd parameter below) is only available in the patched version of the Poco libraries
			Poco::Net::RawSocket     sock (Poco::Net::IPAddress::IPv4, IPPROTO_DIVERT, false);
			sock.bind (Poco::Net::SocketAddress (config().getString ("server.address", "127.0.0.1"), 
												 config().getInt ("server.port", 9999)));

			int           state  = S_IDLE;
			uint16_t      cookie = 0;
			uint16_t      blknum = 0;
			std::ifstream file;

			while (true)
			{
				LOG4CXX_INFO (logger, "waiting for packets...");

				//
				// receive diverted packet from network stack (IP + ICMP + payload)
				//
				Poco::Net::SocketAddress sender;
				buffer.m_size = sock.receiveFrom (buffer.m_addr, MAX_PACKET_SIZE, sender);
				IPPacket ippkt (buffer);
				LOG4CXX_INFO (logger, "IP packet received from " << ippkt.srcAddr());
				LOG4CXX_TRACE (logger, "hex dump of packet:\n" << hexdump (buffer.m_addr, buffer.m_size));

				//
				// extract ICMP packet (we assume we only get ICMP echo requests)
				//
				if (ippkt.protocol() != IPPROTO_ICMP)
				{
					LOG4CXX_DEBUG (logger, "IP packet does not contain an ICMP packet - re-injecting it");
					sock.sendTo (ippkt.packet().m_addr, ippkt.packet().m_size, sender);
				}
				ICMPEchoRequest icmppkt (ippkt.payload());
				LOG4CXX_DEBUG (logger, "ICMP packet extracted");

				//
				// extract TFTP packet and handle it according to the state we're currently in
				//
				TFTP::Packet inpkt (icmppkt.payload());
				LOG4CXX_DEBUG (logger, "TFTP packet extracted: cookie = " << inpkt.cookie() << ", opcode = " << inpkt.opcode());

				while (true)
				{
					LOG4CXX_DEBUG (logger, "state = " << states [state]);

					//
					// S_IDLE
					//
					if (state == S_IDLE)
					{
						// In state S_IDLE only read or write requests are allowed, but only the read request is implemented
						if (inpkt.opcode() == OP_RRQ)
						{
							// We store the cookie and accept subsequent packets only if they have the same cookie.
							// Only a new read requests resets the cookie.
							TFTP::ReqPacket req (icmppkt.payload());
							cookie = req.cookie();
							LOG4CXX_INFO (logger, "received read request from client for file '" << req.fname() << "' with cookie " << req.cookie());

							file.open (req.fname());

							state = S_READY;
							// no break statement because we want to send the first data packet right away
						}
						else
						{
							icmppkt.setPayload (TFTP::ErrorPacket (icmppkt.payload(), cookie, E_ILLEGAL_OPCODE, "illegal opcode").packet());
							LOG4CXX_ERROR (logger, "illegal opcode (expected OP_RRQ) - sending error packet to client");
							break;
						}
					} // S_IDLE


					//
					// S_READY
					//
					else if (state == S_READY)
					{
						std::vector <uint8_t> data (MAX_TFTP_PACKET_SIZE + 1);
						file.read ((char *) data.data(), MAX_TFTP_PACKET_SIZE);

						// We need to set the size of the vector to the number of bytes actually read so the client can detect
						// that all data has been sent (size < MAX_TFTP_PACKET_SIZE)
						data.resize (file.gcount());

						blknum++;
						icmppkt.setPayload (TFTP::DataPacket (icmppkt.payload(), cookie, blknum, data).packet());
						LOG4CXX_INFO (logger, "sending data packet # " << blknum << " to client" );

						state = S_WAIT_FOR_ACK;
						break;
					} // S_READY


					//
					// S_WAIT_FOR_ACK
					//
					else if (state == S_WAIT_FOR_ACK)
					{
						if ((inpkt.opcode() == OP_ACK) && (inpkt.cookie() == cookie))
						{
							TFTP::AckPacket ack (icmppkt.payload());
							LOG4CXX_INFO (logger, "ACK received for data packet # " << ack.blknum());
							if (blknum == ack.blknum())
							{
								if (file.eof())
								{
									LOG4CXX_INFO (logger, "last packet sent => terminating");
									file.close();
									blknum = 0;
									state = S_IDLE;
									break;
								}
								else
								{
									state = S_READY;
									// no break statement because we want to send the next data packet right away
								}
							}
							else
							{
								icmppkt.setPayload (TFTP::ErrorPacket (icmppkt.payload(), cookie, E_UNDEF, "block number in ACK packet does not match").packet());
								LOG4CXX_ERROR (logger, "block number in ACK packet does not match - sending error packet to client");
								file.close();
								blknum = 0;
								state = S_IDLE;
								break;
							}

						}
						else
						{
							icmppkt.setPayload (TFTP::ErrorPacket (icmppkt.payload(), cookie, E_ILLEGAL_OPCODE, "unexpected opcode (expected OP_ACK) or wrong cookie").packet());
							LOG4CXX_ERROR (logger, "unexpected opcode (expected OP_ACK) or wrong cookie - sending error packet to client");
							file.close();
							blknum = 0;
							state = S_IDLE;
							break;
						}
					} // S_WAIT_FOR_ACK
				} // end while

				//
				// re-inject packet into network stack
				//
				ippkt.setPayload (icmppkt.packet());

				sock.sendTo (ippkt.packet().m_addr, ippkt.packet().m_size, sender);
				LOG4CXX_INFO (logger, "IP packet re-injected");
				LOG4CXX_TRACE (logger, "hex dump of packet:\n" << hexdump (ippkt.packet().m_addr, ippkt.packet().m_size));
			} // end while
		}
		catch (std::exception &e)
		{
			LOG4CXX_ERROR (logger, "exception occurred: " << e.what());
			return EXIT_OSERR;
		}
		return EXIT_OK;
	}


	~TFTPServer()
	{
		// TODO: The destructor is currently never called because we don't catch Ctrl-c
		LOG4CXX_INFO (logger, "server is shutting down...");
		delete[] buffer.m_addr;
	}
};



int main (int argc, char ** argv)
{
    TFTPServer server;
    return server.run (argc, argv);
}
