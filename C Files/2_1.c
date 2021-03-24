#include <pcap.h>
#include <stdio.h>
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
struct sockaddr_in source,dest;
void print_ip_header(const u_char * pkt, int Size)
{

	struct iphdr *iph = (struct iphdr *)(pkt  + sizeof(struct ethhdr));
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;
	
	printf("Source IP       : %s\n" , inet_ntoa(source.sin_addr) );
	printf("Destination IP  : %s\n" , inet_ntoa(dest.sin_addr) );
}

void printData (const u_char * data , int size)
{
	int i , j;
	for(i=0 ; i < size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			printf("         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					printf( "%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else printf( "."); //otherwise print a dot
			}
			printf("\n");
		} 
		
	
			printf(" %02X",(unsigned int)data[i]);
				
		if(i==size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
			  printf( "   "); //extra spaces
			}
			
			printf("         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
				  printf( "%c",(unsigned char)data[j]);
				}
				else 
				{
				  printf( ".");
				}
			}
			
			printf( "\n");
		}
	}
}
void print_tcp_packet(const u_char * pkt, int size)
{
	struct iphdr *iph = (struct iphdr *)( pkt  + sizeof(struct ethhdr) );
	unsigned short iph_len;
	iph_len = sizeof(struct iphdr);//iph->ihl*4;

	struct tcphdr *tcph=(struct tcphdr*)(pkt + iph_len + sizeof(struct ethhdr));	//[  ETHERNET | IP | TCP |  DATA  ]	
	int header_len =  sizeof(struct ethhdr) + iph_len +sizeof(struct tcphdr);//+ tcph -> doff*4;

	printf("Source Port     : %u\n", ntohs(tcph -> source));
	printf("Destination Port: %u\n", ntohs(tcph -> dest));
	printf("Data:\n");
	printData(pkt + header_len , size - header_len );
}


//what to do with each packet we get: more functionality to be added is to differentiate between each type of packet(ICMP,TCP,UDP...)
//If that will come to pass we need to add methods to print additonal info on the packet (ETH header, TCP segment, etc..) 
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
	
	int size = header->len;
	// struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr)); 
	print_ip_header(packet, size);

	print_tcp_packet(packet,size);
	
}
int main()
{
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "icmp";
char filter_exp_icmp_2_hosts[] = "icmp and host 10.0.2.15 and host 10.9.0.5";
char filter_exp_ip_tcp_port_10_100[] = "tcp and dst portrange 10-100";
char filter_exp_tcp[] = "tcp and port 23";
bpf_u_int32 net;
// Step 1: Open live pcap session on NIC with name eth3
// Students needs to change "eth3" to the name
// found on their own machines (using ifconfig).
handle = pcap_open_live("br-2b1fb0c14649", BUFSIZ, 1, 1000, errbuf);
// Step 2: Compile filter_exp into BPF psuedo-code
pcap_compile(handle, &fp, filter_exp_tcp, 0, net);
pcap_setfilter(handle, &fp);
// Step 3: Capture packets
pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle); //Close the handle
return 0;
}
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap
