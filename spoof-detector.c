/*
 * spoof-detector.c
 *
 * sends probe packet to suspicious IP-MAC pair and listens for any responses
 * version 0.3 (2011-04-09)
 * 
 ******************************************************************************
 *
 * Code Comments
 *
 ******************************************************************************
 *
 */


#include "config.h"


char *suspicious_ip;
int valid = 0, answer = 0, scn_type, dst_port, verbose = 0;
u_int caplen, length;						/* stores captured packet length and offwire length */


struct validated_queue
*get_node () {

	struct validated_queue *temp = NULL;
	temp = (struct validated_queue *)malloc (sizeof (struct validated_queue));
	temp->ip;
	temp->mac;
	temp->next = NULL;

	return temp;

}//get_node

void
pkt_handler (u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	caplen = header->caplen;				/* length of portion present from bpf  */
	length = header->len;					/* length of this packet off the wire  */

	struct ip_hdr *ip = (struct ip_hdr *)(packet + ETHER_HEADER_LEN);
	char *src_ip = inet_ntoa (ip->ip_src);

	/* if this packet is from the suspicious IP, then parse it further */
	if (0 == strncmp (suspicious_ip, src_ip, sizeof (src_ip))) {

		/* if a TCP reply is received and scan type is one amongst TCP scans, then parse the packet */
		if (IPPROTO_TCP == ip->ip_p && (ACK_SCAN == scn_type || RST_SCAN == scn_type
						|| SYN_SCAN == scn_type || FIN_SCAN == scn_type)) {
			struct tcp_hdr *tcp = (struct tcp_hdr *) (packet + LIBNET_IPV4_H + LIBNET_ETH_H);
			if (dst_port == ntohs (tcp->th_sport)) {
				printf (" [*] received a TCP reply for our probe packet from %s:%d\n",
					src_ip, ntohs (tcp->th_sport));
				answer = 0;
				valid = 1;
				if (1 == verbose) {
					printpayload (packet, caplen);
					printf ("\n");
				}
			}
		}

		/* if an ICMP reply is received and scan type is UDP, then parse the packet */
		if (IPPROTO_ICMP == ip->ip_p && UDP_SCAN == scn_type) {
			/* check for a port unreachable ICMP error (TYPE:3, CODE:3) for a closed UDP port */
			struct icmp_hdr *icmp = (struct icmp_hdr *) (packet + LIBNET_IPV4_H + LIBNET_ETH_H);
			if (DEST_UNREACH == icmp->type && PORT_UNREACH == icmp->code) {
				printf (" [*] received ICMP PORT_UNREACHABLE reply for our probe packet from %s\n",
					src_ip);
				answer = 0;
				valid = 1;
				if (1 == verbose) {
					printpayload (packet, caplen);
					printf ("\n");
				}
			}
		}

		/* if an ICMP reply is received and scan type is ECHO/TSTAMP, then parse the packet */
		if (IPPROTO_ICMP == ip->ip_p && (ECHO_SCAN == scn_type) || (TSTAMP_SCAN == scn_type)) {
			struct icmp_hdr *icmp = (struct icmp_hdr *) (packet + LIBNET_IPV4_H + LIBNET_ETH_H);
			if (ECHO_REPLY == icmp->type && ECHO_SCAN == scn_type) {
				printf (" [*] received an ECHO-REPLY for our probe packet from %s\n", src_ip);
				answer = 0;
				valid = 1;
				if (1 == verbose) {
					printpayload (packet, caplen);
					printf ("\n");
				}
			}

			if (TSTAMP_REPLY == icmp->type && TSTAMP_SCAN == scn_type) {
				printf (" [*] received a TIMESTAMP REPLY for our probe packet from %s\n", src_ip);
				answer = 0;
				valid = 1;
				if (1 == verbose) {
					printpayload (packet, caplen);
					printf ("\n");
				}
			}
		}
	}

}//pkt_handler

int
spoof_detector (struct configuration conf, struct validated_queue *start, struct validated_queue *end) {

	int c = 0, len, flags;

	int pbuf_size = 0;
	u_char frame[1024], *tmp;
	unsigned short int *tmp2;

	char str_flags[9]="[";							/* flags to set while sending TCP probes */
	char *arp_cache_clean;							/* command to clear system ARP cache */
	struct configuration *config = &conf;					/* structures to hold our configuration */

	pcap_t *p;								/* libpcap handle */
	libnet_t *l;								/* libnet handle */

	libnet_ptag_t udp = 0, tcp = 0, icmp = 0, ipv4 = 0, ether = 0;		/* libnet protocol blocks */
	char libpcap_errbuf[PCAP_ERRBUF_SIZE];					/* pcap error messages */
	char libnet_errbuf[LIBNET_ERRBUF_SIZE];					/* libnet error messages */
	u_long udp_size, tcp_size, icmp_size,
		ipv4_size, ether_size, probe_size;				/* size of probe packet */
	u_char *udp_packet, *tcp_packet, *icmp_packet,
		*ipv4_packet, *ether_packet, *probe_packet;			/* stores contents of probe packet */

	in_addr_t destip;							/* stores destip for IP header */

	time_t tv;								/* holds timeout start time */
	char *filter = "tcp || udp || icmp";					/* bpf filter expression */
	struct bpf_program fp;							/* compiled filter expression */
	bpf_u_int32 netp, maskp;						/* netmask and ip */

	struct validated_queue *temp = NULL;					/* pointer to validated queue */

	destip = libnet_name2addr4 (l, config->a_sip, LIBNET_RESOLVE);		/* store sip as destip for IP probe packet */

	/* store config params for pkt_handler */
	scn_type = config->scan_type;
	dst_port = config->dport;
	verbose = config->verbose;

	/* open pcap capture device */
	if ((p = pcap_open_live (config->dev, SNAPLEN, PROMISC, TIME_OUT, libpcap_errbuf)) == NULL) {
		printf ("\n [-] error initializing pcap: %s\n\n", libpcap_errbuf);
		exit (EXIT_FAILURE);
	}

	/* set pcap nonblocking mode */
	if ((pcap_setnonblock (p, 1, libnet_errbuf)) == -1) {
		printf ("\n [-] error setting nonblocking option: %s\n\n", libpcap_errbuf);
		exit (EXIT_FAILURE);
	}

	/* get network id and mask associated with capture device */
	if (pcap_lookupnet (config->dev, &netp, &maskp, libpcap_errbuf) == -1) {
		printf ("\n [-] net/mask lookup error: %s\n\n", libpcap_errbuf);
		exit (EXIT_FAILURE);
	}

	/* compile the capture filter expression */
	if (pcap_compile (p, &fp, filter, 0, maskp) == -1) {
		printf ("\n [-] bpf error: %s\n\n", pcap_geterr (p));
		exit (EXIT_FAILURE);
	}

	/* set compiled filter on pcap handle */
	if (pcap_setfilter (p, &fp) == -1) {
		printf ("\n [-] error setting bpf: %s\n\n", pcap_geterr (p));
		exit (EXIT_FAILURE);
	}

	/* initialize libnet library */
	l = libnet_init (LIBNET_LINK, config->dev, libnet_errbuf);
	if (NULL == l) {
		printf ("\n [-] libnet_init() failed: %s\n\n", libnet_errbuf);
		exit (EXIT_FAILURE);
	}

	/* seed the pseudo random number generator */
	libnet_seed_prand (l);

	printf ("\n [*] initiated spoof-detection logic for current session. requested scan type is: %s\n", config->a_scan_type);

	/* create TCP/IP headers if scan_type is TCP */
	if (ACK_SCAN == config->scan_type || RST_SCAN == config->scan_type || 
		SYN_SCAN == config->scan_type || FIN_SCAN == config->scan_type) {

		flags = config->flags;
		if (ACK == (flags & ACK)) { strncat (str_flags, "A", sizeof (str_flags)); }
		if (RST == (flags & RST)) { strncat (str_flags, "R", sizeof (str_flags)); }
		if (SYN == (flags & SYN)) { strncat (str_flags, "S", sizeof (str_flags)); }
		if (FIN == (flags & FIN)) { strncat (str_flags, "F", sizeof (str_flags)); }
		strncat (str_flags, "]", sizeof (str_flags));

		tcp = libnet_build_tcp (libnet_get_prand (LIBNET_PRu16),
					config->dport, libnet_get_prand (LIBNET_PRu16),
					0,
					config->flags,
					7,
					0,
					0,
					LIBNET_TCP_H,
					NULL,
					0,
					l,
					tcp);

		if (-1 == tcp) {
			printf ("\n [-] unable to build TCP header: %s\n\n", libnet_geterror (l));
			exit (EXIT_FAILURE);
		}

		/* build the IP header */
		ipv4 = libnet_build_ipv4 (LIBNET_TCP_H + LIBNET_IPV4_H,
						0,
						libnet_get_prand (LIBNET_PRu16),
						0,
						64,
						IPPROTO_TCP,
						0,
						config->ipaddr,
						destip,
						NULL,
						0,
						l,
						ipv4);

		if (-1 == ipv4) {
			printf ("\n [-] unable to build IPv4 header: %s\n\n", libnet_geterror (l));
			exit (EXIT_FAILURE);
		}

		/* build the Ethernet header */
		ether = libnet_build_ethernet (libnet_hex_aton (config->a_sha, &len),
						config->macaddr,
						ETHERTYPE_IP,
						NULL,
						NULL,
						l, 
						ether);

		if (-1 == ether) {
			printf ("\n [-] unable to build Ethernet header: %s\n\n", libnet_geterror (l));
			exit (EXIT_FAILURE);
		}

		tmp2 = (unsigned short int *)libnet_getpbuf (l, tcp);
		printf (" [*] created a TCP/IP packet with following fields:\n");
		printf ("\n { TCP: %u > %d %s } { IP: %s > %s } { ETH: %s > %s }\n",
			ntohs (*tmp2), config->dport, str_flags, config->llip, config->a_sip, config->llmac, config->a_sha);

	}

	/* create UDP/IP headers if scan_type is UDP */
	if (UDP_SCAN == config->scan_type) {

		udp = libnet_build_udp (SPORT,
					config->dport,
					LIBNET_UDP_H,
					0,
					NULL,
					NULL,
					l,
					udp);

		if (-1 == udp) {
			printf ("\n [-] unable to build UDP header: %s\n\n", libnet_geterror (l));
			exit (EXIT_FAILURE);
		}

		/* build the IP header */
		ipv4 = libnet_build_ipv4 (LIBNET_UDP_H + LIBNET_IPV4_H,
						0,
						libnet_get_prand (LIBNET_PRu16),
						0,
						64,
						IPPROTO_UDP,
						0,
						config->ipaddr,
						destip,
						NULL,
						0,
						l,
						ipv4);

		if (-1 == ipv4) {
			printf ("\n [-] unable to build IPv4 header: %s\n\n", libnet_geterror (l));
			exit (EXIT_FAILURE);
		}

		/* build the Ethernet header */
		ether = libnet_build_ethernet (libnet_hex_aton (config->a_sha, &len),
						config->macaddr,
						ETHERTYPE_IP,
						NULL,
						NULL,
						l,
						ether);

		if (-1 == ether) {
			printf ("\n [-] unable to build Ethernet header: %s\n\n", libnet_geterror (l));
			exit (EXIT_FAILURE);
		}

		tmp2 = (unsigned short int *)libnet_getpbuf (l, udp);
		printf (" [*] created a UDP/IP packet with following fields:\n");
		printf ("\n { UDP: %u > %d } { IP: %s > %s } { ETH: %s > %s }\n",
			ntohs (*tmp2), config->dport, config->llip, config->a_sip, config->llmac, config->a_sha);

	}

	/* create ICMP/IP headers if scan_type is ECHO_SCAN */
	if (ECHO_SCAN == config->scan_type) {

		icmp = libnet_build_icmpv4_echo (ICMP_ECHO,
							0,
							0,
							(u_int16_t)libnet_get_prand (LIBNET_PR16),
							1,
							NULL,
							NULL,
							l,
							icmp);

		if (-1 == icmp) {
			printf ("\n [-] unable to build ICMP ECHO REQUEST header: %s\n\n", libnet_geterror (l));
			exit (EXIT_FAILURE);
		}

		/* build the IP header */
		ipv4 = libnet_build_ipv4 (LIBNET_ICMPV4_ECHO_H + LIBNET_IPV4_H,
						0,
						libnet_get_prand (LIBNET_PRu16),
						0,
						64,
						IPPROTO_ICMP,
						0,
						config->ipaddr,
						destip,
						NULL,
						0,
						l,
						ipv4);

		if (-1 == ipv4) {
			printf ("\n [-] unable to build IPv4 header: %s\n\n", libnet_geterror (l));
			exit (EXIT_FAILURE);
		}

		/* build the Ethernet header */
		ether = libnet_build_ethernet (libnet_hex_aton (config->a_sha, &len),
						config->macaddr,
						ETHERTYPE_IP,
						NULL,
						NULL,
						l,
						ether);

		if (-1 == ether) {
			printf ("\n [-] unable to build Ethernet header: %s\n\n", libnet_geterror (l));
			exit (EXIT_FAILURE);
		}

		printf (" [*] created an ICMP/IP packet for ICMP ECHO REQUEST with following fields\n");
		printf ("\n { IP: %s > %s } { ETH: %s > %s }\n", config->llip, config->a_sip, config->llmac, config->a_sha);

	}

	if (TSTAMP_SCAN == config->scan_type) {

		icmp = libnet_build_icmpv4_timestamp (ICMP_TSTAMP,
							0,
							0,
							(u_int16_t)libnet_get_prand (LIBNET_PR16),
							1,
							0,
							0,
							0,
							NULL,
							NULL,
							l,
							icmp);

		if (-1 == icmp) {
			printf ("\n [-] unable to build ICMP TIMESTAMP REQUEST header: %s\n\n", libnet_geterror (l));
			exit (EXIT_FAILURE);
		}

		/* build the IP header */
		ipv4 = libnet_build_ipv4 (LIBNET_ICMPV4_TS_H + LIBNET_IPV4_H,
						0,
						libnet_get_prand (LIBNET_PRu16),
						0,
						64,
						IPPROTO_ICMP,
						0,
						config->ipaddr,
						destip,
						NULL,
						0,
						l,
						ipv4);

		if (-1 == ipv4) {
			printf ("\n [-] unable to build IPv4 header: %s\n\n", libnet_geterror (l));
			exit (EXIT_FAILURE);
		}

		/* build the Ethernet header */
		ether = libnet_build_ethernet (libnet_hex_aton (config->a_sha, &len),
						config->macaddr,
						ETHERTYPE_IP,
						NULL,
						NULL,
						l,
						ether);

		if (-1 == ether) {
			printf ("\n [-] unable to build Ethernet header: %s\n\n", libnet_geterror (l));
			exit (EXIT_FAILURE);
		}

		printf (" [*] creating an ICMP/IP packet for TIMESTAMP REQUEST with following fields\n");
		printf ("\n { IP: %s > %s } { ETH: %s > %s }\n", config->llip, config->a_sip, config->llmac, config->a_sha);

	}

	/* store the suspicious IP for later verification */
	suspicious_ip = config->a_sip;

	/* write above packet to wire */
	if ((-1 == libnet_write (l))) {
		printf ("\n [-] unable to send packet: %s\n\n", libnet_geterror (l));
		exit (EXIT_FAILURE);
	} else {
		pbuf_size += libnet_getpbuf_size (l, ipv4);
		pbuf_size += libnet_getpbuf_size (l, ether);

		tmp = libnet_getpbuf (l, ether);
		memcpy ((void *)frame, (void *)tmp, libnet_getpbuf_size (l, ether));

		tmp = libnet_getpbuf (l, ipv4);
		memcpy ((void *)(frame+libnet_getpbuf_size (l, ether)), (void *)tmp, libnet_getpbuf_size (l, ipv4));

		if (ACK_SCAN == config->scan_type || RST_SCAN == config->scan_type || 
			SYN_SCAN == config->scan_type || FIN_SCAN == config->scan_type) {
			tmp = libnet_getpbuf (l, tcp);
			memcpy ((void *)(frame+libnet_getpbuf_size (l, ether)+libnet_getpbuf_size (l, ipv4)),
				(void *)tmp, libnet_getpbuf_size (l, tcp));
			pbuf_size += libnet_getpbuf_size (l, tcp);
		}

		if (UDP_SCAN == config->scan_type) {
			tmp = libnet_getpbuf (l, udp);
			memcpy ((void *)(frame+libnet_getpbuf_size (l, ether)+libnet_getpbuf_size (l, ipv4)),
				(void *)tmp, libnet_getpbuf_size (l, udp));
			pbuf_size += libnet_getpbuf_size (l, udp);
		}

		if (ECHO_SCAN == config->scan_type || TSTAMP_SCAN == config->scan_type) {
			tmp = libnet_getpbuf (l, icmp);
			memcpy ((void *)(frame+libnet_getpbuf_size (l, ether)+libnet_getpbuf_size (l, ipv4)),
				(void *)tmp, libnet_getpbuf_size (l, icmp));
			pbuf_size += libnet_getpbuf_size (l, icmp);
		}

		if (1 == config->verbose) {
			printpayload (frame, pbuf_size);
		}

		printf ("\n [*] above probe packet injected. waiting for reply with %dus timeout\n", config->gtimeout);
	}

	/* set variables for reply flag/counter */
	answer = 1;
	tv = time (NULL);

	/* capture probe reply */
	while (answer) {
		pcap_dispatch (p, 1, pkt_handler, NULL);
		if ((time (NULL) - tv) > config->gtimeout) {
			answer = 0;
			printf (" [*] reply timed-out. no reply recieved from (%s - %s)\n",
				config->a_sip, config->a_sha);
			return valid;
		}
	}

	/* if the IP - MAC pair is found to be valid, add it to our validated queue */
	if (1 == valid) {
		temp = get_node ();
		if (NULL == start) {
			start = temp;
			end = start;
			strncpy (start->ip, config->a_sip, 16);
			strncpy (start->mac, config->a_sha, 18);
		} else {
			strncpy (temp->ip, config->a_sip, 16);
			strncpy (temp->mac, config->a_sha, 18);
			end->next = temp;
			end = temp;
		}
		config->queue_size += 1;

		temp = start;
		printf (" [*] IP - MAC (%s - %s) pair found to be valid. adding it to validated queue\n",
			config->a_sip, config->a_sha);
		printf (" [*] validated IP - MAC pairs queue (queue_size: %d)\n", config->queue_size);
		while (temp) {
			++c;
			printf ("     { (%03d) %s - %s } \n", c, temp->ip, temp->mac);
			temp = temp->next;
		}
	}

	/* close handles and free up resources */
	pcap_freecode (&fp);
	pcap_close (p);
	libnet_destroy (l);

	return valid;

}//spoof-detector


/* EOF */
