/*
 * config.h
 * defines structures and constants used for arp-secur session
 * version 0.3 (2011-04-09)
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "pcap.h"						/* used for defining pcap routines */
#include "libnet.h"						/* used for defining injection routines */

#include "headers.h"						/* to use addr-len constants */

#define CAPLEN		1518					/* maximum length for ethernet header */
#define SNAPLEN		65535
#define PROMISC		0
#define TIME_OUT	2					/* probe reply time-out in usecs */

#define SPORT		8118

#define HTTP		80
#define FTP		21
#define TELNET		23
#define SSH		22
#define SMTP		25

#define ACK_SCAN	1
#define RST_SCAN	2
#define SYN_SCAN	3
#define FIN_SCAN	4
#define UDP_SCAN	5
#define ECHO_SCAN	6
#define TSTAMP_SCAN	7

#define DETECT		0
#define PREVENT		1


struct configuration {

	char *dev;						/* pcap device */
	bpf_u_int32 net, mask;					/* netid and netmask */

	u_char smac[ETHER_ADDR_LEN];				/* ethernet source mac address */
	u_char dmac[ETHER_ADDR_LEN];				/* ethernet destination mac address */

	u_int16_t oper;						/* arp operation */
	u_char sha[ETHER_ADDR_LEN];				/* arp source mac address */
	u_char sip[IP_ADDR_LEN];				/* arp source ip address */
	u_char dha[ETHER_ADDR_LEN];				/* arp destination mac address */
	u_char dip[IP_ADDR_LEN];				/* arp destination ip address */

	char	e_smac[18], e_dmac[18],
		a_sha[18], a_sip[16],
		a_dha[18], a_dip[16];				/* addresses in string notation */

	u_int32_t ipaddr;					/* stores local ip address */
	struct libnet_ether_addr *macaddr;			/* stores local mac address */

	char llmac[18], llip[16];				/* string notations for local mac and ip */

	int mode;						/* 0:DETECT, 1:PREVENT */
	int queue_size;						/* holds validated_queue size */

	int dport;						/* port to scan while spoof detection */
	int gtimeout;						/* probe reply timeout */
	int verbose;						/* whether to display packet contents in TCPDump style */
	int scan_type;						/* spoof detection engine's scan type */
	int flags;						/* TCP flags depending on scan type */
	char *a_port_name, *a_scan_type;			/* string notations for port and scan type */

};

struct validated_queue {

	char ip[16];						/* validated ip address */
	char mac[18];						/* validated mac address */

	struct validated_queue *next;				/* ptr to next element in queue */

};


/* EOF */
