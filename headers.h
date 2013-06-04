/*
 *  headers.h
 *  defines standard protocol headers and constants
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define ETHER_HEADER_LEN	0x0E
#define ETHERTYPE_ARP		0x0806
#define ETHERTYPE_IP		0x0800
#define ETHERTYPE_IP6		0x86dd

#define ARP_HTYPE_ETH		0x0001
#define ARP_PTYPE_IP		0x0001
#define ARP_OPCODE_REQUEST	0x0001
#define ARP_OPCODE_REPLY	0x0002

#define ETH_ADDR_LEN		0x06
#define IP_ADDR_LEN		0x04

#define IP_PROTO_ICMP		0x01
#define IP_PROTO_TCP		0x06
#define IP_PROTO_UDP		0x11
#define IP_PROTO_IPV6		0x29

#define ECHO_REQUEST		0x08
#define ECHO_REPLY		0x00
#define DEST_UNREACH		0x03
#define PORT_UNREACH		0x03

#define TSTAMP_REQUEST		0x0D
#define TSTAMP_REPLY		0x0E

#define CWR	128
#define ECE	64
#define URG	32
#define ACK	16
#define PSH	8
#define RST	4
#define SYN	2
#define FIN	1


typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short int u_int16_t;


/* Ethernet header */
struct ethernet_hdr {

	u_char ether_dmac[ETH_ADDR_LEN];		/* destination mac address */
	u_char ether_smac[ETH_ADDR_LEN];		/* source mac address */
	u_int16_t ether_type;				/* ethertype: arp, rarp, ip ... */

};


/* ARP header */
struct arp_hdr {

	u_int16_t arp_htype;				/* hardware type: ethernet, frame-relay, ... */
	u_int16_t arp_ptype;				/* protocol type: ip, ipx, ... */
	u_char arp_hlen;				/* harware address length: eth-0x06, ... */
	u_char arp_plen;				/* protocol address length: ip-0x04, ... */
	u_int16_t arp_oper;				/* operation: request:0x01, reply:0x02, ... */
	u_char arp_sha[ETH_ADDR_LEN];			/* source hardware address */
	u_char arp_sip[IP_ADDR_LEN];			/* source protocol address */
	u_char arp_dha[ETH_ADDR_LEN];			/* destination hardware address */
	u_char arp_dip[IP_ADDR_LEN];			/* destination protocol address */

};


/* IP header */
struct ip_hdr {
	u_char ip_vhl;			/* version << 4 | header length >> 2 */
	u_char ip_tos;			/* type of service */
	u_short ip_len;			/* total length */
	u_short ip_id;			/* identification */
	u_short ip_off;			/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;			/* time to live */
	u_char ip_p;			/* protocol */
	u_short ip_sum;			/* checksum */
	struct in_addr ip_src, ip_dst;	/* source and dest address */
};
#define IP_HL(ip)	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl) >> 4)


/* ICMP header */
struct icmp_hdr {

	u_char type;
	u_char code;
	u_int16_t cksum;
	u_int16_t id;
	u_int16_t seq;

};


/* UDP header */
struct udp_hdr {

	u_int16_t uh_sport;
	u_int16_t uh_dport;
	u_int16_t uh_len;
	u_int16_t uh_check;

};


/* TCP header */
typedef u_int tcp_seq;
struct tcp_hdr {
	u_short th_sport;		/* source port */
	u_short th_dport;		/* destination port */
	tcp_seq th_seq;			/* sequence number */
	tcp_seq th_ack;			/* acknowledgement number */
	u_char th_offx2;		/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN  0x01
	#define TH_SYN  0x02
	#define TH_RST  0x04
	#define TH_PSH	0x08
	#define TH_ACK  0x10
	#define TH_URG  0x20
	#define TH_ECE  0x40
	#define TH_CWR  0x80
	#define TH_FLAGS	(TH_FIN|TH_SYN|TH_RST|TH_PSH|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;			/* window */
	u_short th_sum;			/* checksum */
	u_short th_urp;			/* urgent pointer */
};



/* EOF */
