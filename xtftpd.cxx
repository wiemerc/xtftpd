//
// Proof-of-concept for a TFTP server (see RFC 1350 for details) written in C++ which uses ICMP packets as transport. It uses the netfilter_queue 
// library to process ICMP packets in userspace.
//
// Copyright(C) 2013 Constantin Wiemer



//
// header files
//
#include <fstream>
#include <exception>
#include <stdexcept>
#include <vector>
#include <string>
#include <cstdio>

#include "log4cxx/logger.h"
#include "log4cxx/propertyconfigurator.h"

#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>


using namespace std;


// TODO: cleanup code (unsigned / signed, const / non-const arguments, namespaces...)
//
// constants
//

const unsigned int MAX_DATA_SIZE   = 56;
const unsigned int MAX_PACKET_SIZE = 1024;
const unsigned int IP_HDR_SIZE     = 20;
const unsigned int ICMP_HDR_SIZE   = 8;

// opcodes
const uint16_t OP_RRQ	 = 1;
const uint16_t OP_WRQ	 = 2;
const uint16_t OP_DATA	 = 3;
const uint16_t OP_ACK	 = 4;
const uint16_t OP_ERROR  = 5;

// states
const unsigned int S_IDLE         = 0;
const unsigned int S_READY        = 1;
const unsigned int S_WAIT_FOR_ACK = 2;
const unsigned int S_SEND_ACK     = 3;
const unsigned int S_RETRY        = 4;
const unsigned int S_ERROR        = 5;
const unsigned int S_TERMINATED   = 6;

// error codes
const unsigned int E_UNDEF          = 0;
const unsigned int E_FILE_NOT_FOUND = 1;
const unsigned int E_ACCESS_DENIED  = 2;
const unsigned int E_DISK_FULL      = 3;
const unsigned int E_ILLEGAL_OPCODE = 4;
const unsigned int E_FILE_EXISTS    = 6;
// The following codes not defined in the RFC
const unsigned int E_TIMEOUT        = 8;
const unsigned int E_FILE_TOO_BIG   = 9;


//
// global variables
//
log4cxx::LoggerPtr logger (log4cxx::Logger::getLogger ("tftpd"));
extern "C" int accept_packet (struct nfq_q_handle *, struct nfgenmsg *, struct nfq_data *, void *);
unsigned short chksum (unsigned char *, unsigned int);
string hexdump (const vector <unsigned char> &);


//
// classes representing a TFTP packet, different classes for different opcodes
//
class TFTPPacket
{
        virtual void encode()
        {

            bytes.push_back ((unsigned char) (cookie >> 8));
            bytes.push_back ((unsigned char) (cookie & 0x00ff));
            bytes.push_back ((unsigned char) (opcode >> 8));
            bytes.push_back ((unsigned char) (opcode & 0x00ff));
        }


        virtual void decode()
        {
            cookie = (bytes[0] << 8) + bytes[1];
            opcode = (bytes[2] << 8) + bytes[3];
        }


    public:
        vector <unsigned char> bytes;
        unsigned short         cookie;
        unsigned short         opcode;

        // default constructor
        TFTPPacket()
        {
        }


        // construct object from packet bytes
        TFTPPacket (const vector <unsigned char> & bytes) : bytes (bytes)
        {
            decode();
        }


        // construct object from parameters
        TFTPPacket (unsigned short cookie, unsigned int opcode) : cookie (cookie), opcode (opcode)
        {
            encode();
        }
};



class TFTPReqPacket : public TFTPPacket
{
        void encode()
        {
            // TODO
        }


        void decode()
        {
            unsigned int i = 4;
            for (i; i < bytes.size(); i++)
            {
                if (bytes[i] > 0)
                    fname.append (1, bytes[i]);
                else
                    break;
            }
            i++;
            for (i; i < bytes.size(); i++)
            {
                if (bytes[i] > 0)
                    mode.append (1, bytes[i]);
                else
                    break;
            }
        }


    public:
        std::string fname;
        std::string mode;


        TFTPReqPacket (const vector <unsigned char> & bytes) : TFTPPacket (bytes)
        {
            decode();
        }
};



class TFTPDataPacket : public TFTPPacket
{
        void encode()
        {
            bytes.push_back ((unsigned char) (blknum >> 8));
            bytes.push_back ((unsigned char) (blknum & 0x00ff));
            for (unsigned int i = 0; i < data.size(); i++)
                bytes.push_back ((unsigned char) data[i]);
        }


        void decode()
        {
            // TODO
        }


    public:
        unsigned short     blknum;
        std::vector <char> data;


        TFTPDataPacket (const vector <unsigned char> & bytes) : TFTPPacket (bytes)
        {
            decode();
        }


        TFTPDataPacket (unsigned short cookie, unsigned int blknum, const vector <char> & data) : TFTPPacket (cookie, OP_DATA), blknum (blknum), data (data)
        {
            encode();
        }
};



class TFTPAckPacket : public TFTPPacket
{
        void encode()
        {
            bytes.push_back ((unsigned char) (blknum >> 8));
            bytes.push_back ((unsigned char) (blknum & 0x00ff));
        }


        void decode()
        {
            blknum = (bytes[4] << 8) + bytes[5];
        }

    public:
        unsigned short blknum;


        TFTPAckPacket (const vector <unsigned char> & bytes) : TFTPPacket (bytes)
        {
            decode();
        }


        TFTPAckPacket (unsigned short cookie, unsigned int blknum) : TFTPPacket (cookie, OP_ACK), blknum (blknum)
        {
            encode();
        }
};



class TFTPErrorPacket : public TFTPPacket
{
        void encode()
        {
            bytes.push_back ((unsigned char) (errcode >> 8));
            bytes.push_back ((unsigned char) (errcode & 0x00ff));
            for (unsigned int i = 0; i < errmsg.length(); i++)
                bytes.push_back ((unsigned char) errmsg[i]);
            bytes.push_back (0);
        }


        void decode()
        {
            // TODO
        }


    public:
        unsigned short errcode;
        std::string  errmsg;


        TFTPErrorPacket (unsigned short cookie, unsigned int errcode, const string & errmsg) : TFTPPacket (cookie, OP_ERROR), errcode (errcode), errmsg (errmsg)
        {
            encode();
        }
};



//
// class that implements all the server functionality
//
class TFTPServer
{
        struct nfq_handle *   hnd;
        struct nfq_q_handle * qhnd;
        TFTPPacket            inpkt, outpkt;
        unsigned short        cookie;
        unsigned int          state;
        unsigned short          blknum;
        std::ifstream         fh;

	public:
        TFTPServer()
        {
            state  = S_IDLE;
            blknum = 0;
        }


        void init()
        {
		    LOG4CXX_INFO (logger, "server is starting up...");

            // open queue handler
            if (!(hnd = nfq_open()))
            {
                LOG4CXX_ERROR (logger, "could not open queue handler");
                throw std::runtime_error::runtime_error ("initialization error");
            }

            // unbind existing queue handler for AF_INET (if any)
            if (nfq_unbind_pf (hnd, AF_INET) < 0) 
            {
                LOG4CXX_ERROR (logger, "could not unbind existing queue handler");
                throw std::runtime_error::runtime_error ("initialization error");
            }

            // bind queue handler for AF_INET
            if (nfq_bind_pf (hnd, AF_INET) < 0) 
            {
                LOG4CXX_ERROR (logger, "could not bind queue handler");
                throw std::runtime_error::runtime_error ("initialization error");
            }

            // create new queue handle for queue # 0
            // As the callback function needs to be a function with C linking and not a class method there is a function accept_packet(). This function
            // gets passed a pointer to the TFTPServer object (last argument below) and just calls the TFTPServer::handle_packet() method.
            if (!(qhnd = nfq_create_queue (hnd, 0, &accept_packet, this)))
            {
                LOG4CXX_ERROR (logger, "could not create queue handle");
                throw std::runtime_error::runtime_error ("initialization error");
            }

            // enable copy mode (whole packet is copied to user space)
            if (nfq_set_mode (qhnd, NFQNL_COPY_PACKET, 0xffff) < 0) 
            {
                LOG4CXX_ERROR (logger, "could not set mode");
                throw std::runtime_error::runtime_error ("initialization error");
            }

            LOG4CXX_INFO (logger, "initialization finished - waiting for packets");
        }


        void handle_packet (struct nfq_data * phnd)
        {
            int                           pktid = 0;
            struct nfqnl_msg_packet_hdr * phdr;
            char *                        pdata;
            int                           psize;
            TFTPPacket                    outpkt;

            phdr = nfq_get_msg_packet_hdr (phnd);
            if (phdr)
                pktid = ntohl (phdr->packet_id);

            psize = nfq_get_payload (phnd, &pdata);
            LOG4CXX_DEBUG (logger, "received packet with " << psize << " bytes of payload");
            LOG4CXX_DEBUG (logger, "hex dump of packet:" << "\n" << hexdump (std::vector <unsigned char> (pdata, pdata + psize)));

            //
            // decode packet
            //
            // We assume here:
            // (1) no Ethernet header (Is this always the case?)
            // (2) fixed IP header length of 20 bytes
            // (3) ICMP echo request with a length of 8 bytes
            TFTPPacket inpkt (std::vector <unsigned char> (pdata + IP_HDR_SIZE + ICMP_HDR_SIZE, pdata + psize));
            LOG4CXX_DEBUG (logger, "cookie = " << inpkt.cookie);
            LOG4CXX_DEBUG (logger, "opcode = " << inpkt.opcode);

            //
            // process packet
            //
            // TODO: handle errors, timeouts and retries
            // TODO: set cookie in outgoing packet
            // TODO: pad / truncate outgoing packet to the size of the incoming packet
		    try
		    {
                while (true)
                {
                    LOG4CXX_DEBUG (logger, "state = " << state);

                    //
                    // S_IDLE
                    //
                    if (state == S_IDLE)
                    {
                        // In state S_IDLE only read or write requests are allowed, but we only implement the read request
                        if (inpkt.opcode == OP_RRQ)
                        {
                            LOG4CXX_INFO (logger, "received read request from client with cookie " << inpkt.cookie);

                            // We store the cookie and accept subsequent requests only if they have the same cookie. Only a new read requests resets
                            // the cookie.
                            cookie = inpkt.cookie;

                            TFTPReqPacket req (inpkt.bytes);
                            LOG4CXX_DEBUG (logger, "fname = " << req.fname);
                            LOG4CXX_DEBUG (logger, "mode = " << req.mode);

                            fh.open (req.fname.c_str());
                            state = S_READY;
                            LOG4CXX_DEBUG (logger, "changed state to S_READY");
                            // no break statement because we want to send the first data packet right away
                        }
                        else
                        {
                            outpkt = TFTPErrorPacket (cookie, E_ILLEGAL_OPCODE, "illegal opcode");
                            LOG4CXX_INFO (logger, "illegal opcode (expected OP_RRQ) - sending error packet to client");
                            break;
                        }
                    } // S_IDLE


                    //
                    // S_READY
                    //
                    else if (state == S_READY)
                    {
                        std::vector <char> data (MAX_DATA_SIZE + 1);
                        fh.read (data.data(), MAX_DATA_SIZE);

                        // We need to set the size of the vector to the number of bytes actually read so the client can detect that all data
                        // has been sent (size < MAX_DATA_SIZE)
                        data.resize (fh.gcount());
                        blknum++;

                        outpkt = TFTPDataPacket (cookie, blknum, data);
                        LOG4CXX_INFO (logger, "sending data packet # " << blknum << " to client");

                        state = S_WAIT_FOR_ACK;
                        LOG4CXX_DEBUG (logger, "changed state to S_WAIT_FOR_ACK");
                        break;
                    } // S_READY


                    //
                    // S_WAIT_FOR_ACK
                    //
                    else if (state == S_WAIT_FOR_ACK)
                    {
                        if ((inpkt.opcode == OP_ACK) && (inpkt.cookie == cookie))
                        {
                            TFTPAckPacket ack (inpkt.bytes);
                            LOG4CXX_DEBUG (logger, "ACK received for data packet # " << ack.blknum);
                            if (blknum == ack.blknum)
                            {
                                if (fh.eof())
                                {
                                    LOG4CXX_DEBUG (logger, "last packet sent => terminating");
                                    fh.close();
                                    blknum = 0;

                                    // Normally we would not send an answer, but we need to send an answer to the ICMP echo request, so we tell the 
                                    // kernel to process the original packet normally 
                                    nfq_set_verdict (qhnd, pktid, NF_ACCEPT, 0, NULL);

                                    state = S_IDLE;
                                    LOG4CXX_DEBUG (logger, "changed state to S_IDLE");
                                    break;
                                }
                                else
                                {
                                    state = S_READY;
                                    LOG4CXX_DEBUG (logger, "changed state to S_READY");
                                    // no break statement because we want to send the next data packet right away
                                }
                            }
                            else
                            {
                                outpkt = TFTPErrorPacket (cookie, E_UNDEF, "block number or cookie in ACK packet does not match");
                                LOG4CXX_INFO (logger, "block number or cookie in ACK packet does not match - sending error packet to client");

                                fh.close();
                                blknum = 0;
                                state = S_IDLE;
                                LOG4CXX_DEBUG (logger, "changed state to S_IDLE");
                                break;
                            }

                        }
                        else
                        {
                            outpkt = TFTPErrorPacket (cookie, E_ILLEGAL_OPCODE, "unexpected opcode (expected OP_ACK)");
                            LOG4CXX_INFO (logger, "unexpected opcode (expected OP_ACK) - sending error packet to client");

                            fh.close();
                            blknum = 0;
                            state = S_IDLE;
                            LOG4CXX_DEBUG (logger, "changed state to S_IDLE");
                            break;
                        }
                    } // S_WAIT_FOR_ACK
                }
		    }

		    catch (std::exception &e)
		    {
				LOG4CXX_ERROR (logger, "error occurred: " << e.what());

                // tell the kernel to process the original packet normally 
                nfq_set_verdict (qhnd, pktid, NF_ACCEPT, 0, NULL);
		    }

            //
            // send answer to client as payload of received packet
            // That means we need to create a new packet with the IP and ICMP headers of the original packet plus the TFTP packet that is the answer.
            // In addition, we need to recalculate the ICMP checksum, set the length of the whole packet in the IP header and then recalculate the
            // IP checksum.
            //
            std::vector <unsigned char> answer (pdata, pdata + IP_HDR_SIZE + ICMP_HDR_SIZE);
            answer.insert (answer.end(), outpkt.bytes.begin(), outpkt.bytes.end());
            unsigned char * p = answer.data();

            // recalculate ICMP checksum (header *and* data)
            *((short *) (p + IP_HDR_SIZE + 2)) = 0;
            *((short *) (p + IP_HDR_SIZE + 2)) = chksum (p + IP_HDR_SIZE, answer.size() - IP_HDR_SIZE);

            // set packet length in IP header and recalculate IP checksum (header only)
            *((short *) (p + 10)) = 0;
            *((short *) (p +  2)) = htons (answer.size());
            *((short *) (p + 10)) = chksum (p, IP_HDR_SIZE);

            LOG4CXX_DEBUG (logger, "sending packet with " << answer.size() << " bytes");
            LOG4CXX_DEBUG (logger, "hex dump of packet:" << "\n" << hexdump (answer));
            nfq_set_verdict (qhnd, pktid, NF_ACCEPT, answer.size(), answer.data());
        }


		~TFTPServer()
		{
            // The destructor is currently never called because we don't catch any signals
		    LOG4CXX_INFO (logger, "server is shutting down...");
		}


        void run()
        {
            // get the file descriptor associated with the queue handler
            int fd = nfq_fd (hnd);

            // main loop - wait for packets that have been passed to us by the kernel and process them
            char buf [MAX_PACKET_SIZE] __attribute__ ((aligned));
            int  rv;
            while ((rv = recv (fd, buf, MAX_PACKET_SIZE, 0)) && rv >= 0) 
            {
                LOG4CXX_DEBUG (logger, "packet received from kernel");
                nfq_handle_packet (hnd, buf, rv);
            }
        }
};


//
// callback function which is called for each packet received - just calls the TFTPServer::handle_packet() method
//
extern "C" int accept_packet (struct nfq_q_handle * qh,
                              struct nfgenmsg *     nfmsg,
                              struct nfq_data *     phnd,
                              void *                srv)
{
    LOG4CXX_DEBUG (logger, "callback function was called");
    ((TFTPServer *) srv)->handle_packet (phnd);

    return 0;
}


//
// calculate IP / ICMP checksum
//
unsigned short chksum (unsigned char * bytes, unsigned int len)
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
// create hex dump of a buffer
//
string hexdump (const vector <unsigned char> & bytes)
{
    string  dump;
    char    fmtbuf[10];

    unsigned int pos = 0;
    while (pos < bytes.size())
    {
        snprintf (fmtbuf, 10, "%04x: ", pos);
        dump += string (fmtbuf);
        string line;
        for (unsigned int i = pos; (i < pos + 16) && (i < bytes.size()); i++)
        {
            snprintf (fmtbuf, 10, "%02x ", bytes[i]);
            dump += string (fmtbuf);
            if (bytes[i] >= 0x20 && bytes[i] <= 0x7e)
            {
                line.append (1, bytes[i]);
            }
            else
            {
                line.append (1, '.');
            }
        }
        if (line.length() < 16)
        {
            dump.append (3 * (16 - line.length()), ' ');
        }
        dump.append (1, '\t');
        dump += line;
        dump.append (1, '\n');
        pos += 16;
    }
    return dump;
}



int main (int argc, char ** argv)
{
    // setup logging
    log4cxx::PropertyConfigurator::configure ("logging.properties");

	// start server
    // TODO: catch SIGINTR (Ctrl-C)
    TFTPServer server;
    server.init();
    server.run();

    return 0;
}
