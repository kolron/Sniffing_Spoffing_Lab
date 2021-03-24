// icmp.cpp
// Robert Iakobashvili for Ariel uni, license BSD/MIT/Apache
// 
// Sending ICMP Echo Requests using Raw-sockets.
//

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <errno.h>




 // IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8 

// Checksum algo
unsigned short calculate_checksum(unsigned short * paddress, int len);

// 1. Change SOURCE_IP and DESTINATION_IP to the relevant
//     for your computer
// 2. Compile it using MSVC compiler or g++
// 3. Run it from the account with administrative permissions,
//    since opening of a raw-socket requires elevated preveledges.
//
//    On Windows, right click the exe and select "Run as administrator"
//    On Linux, run it as a root or with sudo.
//
// 4. For debugging and development, run MS Visual Studio (MSVS) as admin by
//    right-clicking at the icon of MSVS and selecting from the right-click 
//    menu "Run as administrator"
//
//  Note. You can place another IP-source address that does not belong to your
//  computer (IP-spoofing), i.e. just another IP from your subnet, and the ICMP
//  still be sent, but do not expect to see ICMP_ECHO_REPLY in most such cases
//  since anti-spoofing is wide-spread.


int spoof_reply(char * src,char * dst, u_char * pkt, char * rec_data, uint16_t id, uint16_t seq)
{
    struct ip iphdr; // IPv4 header
    struct icmp icmphdr; // ICMP-header
    struct icmphdr *icmp;
    
    char data[56];
    memcpy(data, rec_data,56);

    //==================
    // IP header
    //==================

    // IP protocol version (4 bits)
    iphdr.ip_v = 4;

    // IP header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / 4; // not the most correct

    // Type of service (8 bits) - not using, zero it.
    iphdr.ip_tos = 0;

    // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
    iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + 56);

    // ID sequence number (16 bits): not in use since we do not allow fragmentation
    iphdr.ip_id = 0;

    // Fragmentation bits - we are sending short packets below MTU-size and without 
    // fragmentation
    int ip_flags[4];

    // Reserved bit
    ip_flags[0] = 0;

    // "Do not fragment" bit
    ip_flags[1] = 0;

    // "More fragments" bit
    ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    iphdr.ip_off = htons ((ip_flags[0] << 15) + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13) +  ip_flags[3]);

    // TTL (8 bits): 128 - you can play with it: set to some reasonable number
    iphdr.ip_ttl = 128;

    // Upper protocol (8 bits): ICMP is protocol number 1
    iphdr.ip_p = IPPROTO_ICMP;

    // Destination IP
    if (inet_pton (AF_INET, dst, &(iphdr.ip_src)) <= 0) 
    {
        fprintf (stderr, "inet_pton() failed for source-ip with error: %d", errno);
        return -1;
    }

    // Source IP
    if (inet_pton (AF_INET, src, &(iphdr.ip_dst)) <= 0)
    {
        fprintf (stderr, "inet_pton() failed for destination-ip with error: %d" , errno);
        return -1;
    }

    // IPv4 header checksum (16 bits): set to 0 prior to calculating in order not to include itself.
    iphdr.ip_sum = 0;
    iphdr.ip_sum = calculate_checksum((unsigned short *) &iphdr, IP4_HDRLEN);


    // //===================
    // // ICMP header
    // //===================

    // // Message Type (8 bits): ICMP_ECHOREPLY
     icmphdr.icmp_type = ICMP_ECHOREPLY;

    // // Message Code (8 bits): echo request
     icmphdr.icmp_code = 0;

    
     icmphdr.icmp_id = id; 

    // // Sequence Number (16 bits): starts at 0
     icmphdr.icmp_seq = seq;

    // // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
     icmphdr.icmp_cksum = 0;

    // // Combine the packet 
     char packet[IP_MAXPACKET];

    // // First, IP header.
     memcpy (packet, &iphdr, IP4_HDRLEN);

    // // Next, ICMP header
     memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

    // // After ICMP header, add the ICMP data.
     memcpy (packet + IP4_HDRLEN + ICMP_HDRLEN, data, 56);

    // // Calculate the ICMP header checksum
     icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet + IP4_HDRLEN), ICMP_HDRLEN + 56);
     memcpy ((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;

    



    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) 
    {
        fprintf (stderr, "socket() failed with error: %d", errno);

        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    // This socket option IP_HDRINCL says that we are building IPv4 header by ourselves, and
    // the networking in kernel is in charge only for Ethernet header.
    //
    const int flagOne = 1;
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &flagOne, sizeof (flagOne)) == -1) 
    {
        fprintf (stderr, "setsockopt() failed with error: %d", errno);
        return -1;
    }
int sent = 0;
    // Send the packet using sendto() for sending datagrams.
    if (sent += sendto (sock, packet, IP4_HDRLEN + ICMP_HDRLEN + 56, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) < 0)  
    {
        fprintf (stderr, "sendto() failed with error: %d", errno);
        return -1;
    }
  
  // Close the raw socket descriptor.


  return 0;
}

struct sockaddr_in src, dst;
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
    struct iphdr * iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct icmphdr *icmphdr = (struct icmphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
	memset(&src, 0, sizeof(src));
	src.sin_addr.s_addr = iph->saddr;
	memset(&dst, 0, sizeof(dst));
	dst.sin_addr.s_addr = iph->daddr;
    char srcadd[INET_ADDRSTRLEN];
    char dstadd[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(src.sin_addr), srcadd, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(dst.sin_addr), dstadd, INET_ADDRSTRLEN);
    printf("source address before swap is: %s\n", srcadd);
    printf("dest address before swap is: %s\n", dstadd);
    
    char * icmpdata = (char *)((char *)icmphdr + sizeof(struct icmphdr)); 
    uint16_t id = icmphdr-> un.echo.id;
    uint16_t seq = icmphdr -> un.echo.sequence;
   
    spoof_reply(srcadd, dstadd, (u_char *)packet, icmpdata, id, seq);

}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}
int main()
{
pcap_t *handle, *handle2;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "icmp";
bpf_u_int32 net;

handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
handle2 = pcap_open_live("br-2b1fb0c14649", BUFSIZ, 1, 1000, errbuf);
pcap_compile(handle, &fp, filter_exp, 0, net);
pcap_setfilter(handle, &fp);
pcap_loop(handle2, -1, got_packet, NULL);
pcap_close(handle); //Close the handle
return 0;
}



