/*
 * main.c
 *
 * application to detect and prevent arp cache poisoning
 * version 0.3 (2011-04-09)
 * 
 **************************************************************************************************************************
 * 
 * Example compiler command-line for GCC:
 * gcc headers.h pcap_utils.h config.h arp-sniffer.c anamoly-detector.c spoof-detector.c main.c -lpcap -lnet -o arp-secur
 * 
 **************************************************************************************************************************
 *
 * Code Comments
 *
 **************************************************************************************************************************
 *
 */


#define APP_NAME		"arp-secur"
#define APP_VERS		"v0.3"
#define APP_QUOTE		"aut inveniam viam aut faciam"
#define APP_COPYLEFT		"Copyleft (ALL WRONGS RESERVED)"

#include "config.h"
#include "banners.h"						/* few 7337 ascii-art banners for arp-secur */


int
print_banner (void) {

	int index;

	srand (time (NULL));
	index = ((rand () % BANNER_COUNT) + 1);
	banner (index);

	printf ("\n %s (%s) - %s\n", APP_NAME, APP_VERS, APP_QUOTE);
	printf (" %s\n", APP_COPYLEFT);
	printf ("\n");

	return 0;

}//banner

int
print_usage (void) {

	print_banner ();

	printf (" usage: ./%s [options]\n\n", APP_NAME);

	printf (" UDP SCAN MODE:\n -u\t\t\tenables UDP scan mode [sends UDP probes]\n");

	printf (" TCP SCAN MODES:\n -a\t\t\tenables ACK scan mode [TCP - ACK flag set]\n");
	printf (" -r\t\t\tenables RST scan mode [TCP - RST flag set]\n");
	printf (" -s\t\t\tenables SYN scan mode [TCP - SYN flag set]\n");
	printf (" -f\t\t\tenables FIN scan mode [TCP - FIN flag set]\n");

	printf (" ICMP SCAN MODES:\n -e\t\t\tenables ECHO scan mode [sends ICMP ECHO-REQUESTS]\n");
	printf (" -t\t\t\tenables TSTAMP scan mode [sends ICMP TIMESTAMP-REQUESTS]\n");

	printf (" MISC:\n -i <device>\t\tnetwork interface to use for arp-secur session\n");
	printf (" -p <port_number>\tTCP / UDP port to use for the probe packet (1 - 65535)\n");
	printf (" -P\t\t\tenables PREVENT mode to auto-delete poisoned entries from ARP cache\n");
	printf (" -o\t\t\tenables summary popup for current session\n");
	printf (" -g\t\t\tsets reply time-out in usecs for probe packets (1 - 9)\n");
	printf (" -v\t\t\tenables TCPDUMP-like HEX - ASCII layout of packet contents\n\n");

	return 0;

}//usage

int
known_traffic_filter (struct validated_queue *start, char *ip, char *mac, int size) {

	struct validated_queue *temp = start;

	printf (" [*] searching for IP (%s) in validated queue. queue size is %d\n", ip, size);
	while (temp) {
		temp = temp->next;
	}

	return 0;

}//known-traffic-filter

int
cache_cleanup (char *ip, char *mac) {

	char cache_clean[36] = "arp -d ";
	strncat (cache_clean, ip, sizeof (cache_clean));
	system (cache_clean);
	printf (" [+] deleted entry for IP (%s) - MAC (%s) pair from arp cache\n", ip, mac);

}//cache_cleanup

int
alert (char *ip, char *mac, int valid) {

	char *user = "7h3rAm";
	char *cmd = " -c \'notify-send -t 9000 -u critical -i gtk-dialog-info \"ALERT\" \"`tail -n1 /tmp/messages`\"\'";
	char summary[512] = "", message[512] = "logger -t arp-secur \"";

	/* if IP - MAC pair is found to be vaid / invalid, display appropriate pop up message */
	if (1 == valid) {
		strncat (message, ip, sizeof (message));
		strncat (message, " - ", sizeof (message));
		strncat (message, mac, sizeof (message));
		strncat (message, " found to be valid\"", sizeof (message));

		strncat (summary, "su - ", sizeof (summary));
		strncat (summary, user, sizeof (summary));
		strncat (summary, cmd, sizeof (summary));

		system (message);
		system ("cp /var/log/messages /tmp/messages");
		system ("chmod 777 /tmp/messages");
		system (summary);
		system ("rm -rf /tmp/messages");
	} else if (0 == valid) {
		strncat (message, ip, sizeof (message));
		strncat (message, " - ", sizeof (message));
		strncat (message, mac, sizeof (message));
		strncat (message, " found to be invalid\"", sizeof (message));

		strncat (summary, "su - ", sizeof (summary));
		strncat (summary, user, sizeof (summary));
		strncat (summary, cmd, sizeof (summary));

		system (message);
		system ("cp /var/log/messages /tmp/messages");
		system ("chmod 777 /tmp/messages");
		system (summary);
		system ("rm -rf /tmp/messages");
	}

}//alert


int
main (int argc, char **argv) {

	int c, valid, bnr = 9, showpopup = 0, flags = 0;			/* temporary vars */
	char errbuf[PCAP_ERRBUF_SIZE];						/* error buffer */

	libnet_t *l;								/* libnet handle for address retrieval */
	char libnet_errbuf[LIBNET_ERRBUF_SIZE];					/* libnet error messages */

	char start_time[24], end_time[24];
	time_t acurtime, bcurtime;
	struct tm *aloctime, *bloctime;

	struct configuration conf, *config=&conf;				/* struct to hold config for current session */
	struct validated_queue *start = NULL, *end = NULL;			/* pointers to validated queue */

	/* get current system time */
	acurtime = time (NULL);

	/* convert it to local time representation */
	aloctime = localtime (&acurtime);

	/* format time struct into a char array */
	strftime (start_time, 24, "%d/%b/%Y %H:%M:%S", aloctime);

	/* load default params in config struct */
	config->flags = 0;
	config->verbose = 0;
	config->queue_size = 0;
	config->dev = NULL;
	config->dport = HTTP;
	config->mode = DETECT;
	config->gtimeout = TIME_OUT;
	config->scan_type = SYN_SCAN;

	config->a_port_name = "HTTP";
	config->a_scan_type = "SYN_SCAN";

	/* parse and load cmd-line params in config struct */
	while ((c = getopt (argc, argv, "hi:p:Parsfuetvg:o")) != -1) {
		switch (c) {
			case 'h':
				print_usage ();
				exit (EXIT_SUCCESS);
			case 'i':
				config->dev = optarg;
				break;
			case 'p':
				if (1 <= atoi (optarg) && 65535 >= atoi (optarg)) {
					config->dport = atoi (optarg);
				}
				break;
			case 'P':
				config->mode = PREVENT;
				break;
			case 'a':
				config->scan_type = ACK_SCAN;
				config->flags = config->flags | ACK;
				flags = flags | ACK;
				break;
			case 'r':
				config->scan_type = RST_SCAN;
				config->flags = config->flags | RST;
				flags = flags | RST;
				break;
			case 's':
				config->scan_type = SYN_SCAN;
				config->flags = config->flags | SYN;
				flags = flags | SYN;
				break;
			case 'f':
				config->scan_type = FIN_SCAN;
				config->flags = config->flags | FIN;
				flags = flags | FIN;
				break;
			case 'u':
				config->scan_type = UDP_SCAN;
				config->a_scan_type = "UDP_SCAN";
				break;
			case 'e':
				config->scan_type = ECHO_SCAN;
				config->a_scan_type = "ECHO_SCAN";
				break;
			case 't':
				config->scan_type = TSTAMP_SCAN;
				config->a_scan_type = "TSTAMP_SCAN";
				break;
			case 'v':
				config->verbose = 1;
				break;
			case 'g':


				if (1 <= atoi (optarg) && 9 >= atoi (optarg)) {
					config->gtimeout = atoi (optarg);
				}
				break;
			case 'o':
				showpopup = 1;
				break;
			case '?':
				if ('i' == optopt || 'p' == optopt) {
					print_usage ();
					exit (EXIT_FAILURE);
				} else if (isprint (optopt)) {
					printf ("\n [-] unknown option `-%c'\n", optopt);
					print_usage ();
					exit (EXIT_FAILURE);
				} else {
					printf ("\n unknown option character `\\x%x'\n", optopt);
					print_usage ();
					exit (EXIT_FAILURE);
				}
			default:
				print_usage ();
				exit (EXIT_FAILURE);
		}
	}

	if (0 == flags) { config->flags = SYN; }
	else if (ACK == flags) { config->a_scan_type = "ACK_SCAN"; }
	else if (RST == flags) { config->a_scan_type = "RST_SCAN"; }
	else if (SYN == flags) { config->a_scan_type = "SYN_SCAN"; }
	else if (FIN == flags) { config->a_scan_type = "FIN_SCAN"; }

	/* print an ASCII-ART banner */
	print_banner ();

	switch (config->dport) {
		case HTTP:
				config->a_port_name = "HTTP";
				break;
		case FTP:
				config->a_port_name = "FTP";
				break;
		case TELNET:
				config->a_port_name = "TELNET";
				break;
		case SSH:
				config->a_port_name = "SSH";
				break;
		case SMTP:
				config->a_port_name = "SMTP";
				break;
		default:
				config->a_port_name = "UNKNOWN";
				break;
	}

	/* check if we are root, else exit */
	if (0 != getuid ()) {
		printf ("\n [!] you need to be root buddy...\n\n");
		exit (EXIT_FAILURE);
	}

	/* find a capture device if not specified on command-line */
	if (config->dev == NULL) {
		config->dev = pcap_lookupdev (errbuf);
		if (config->dev == NULL) {
			printf ("\n [-] could not find default device: %s\n\n", errbuf);
			exit (EXIT_FAILURE);
		}
	}

	/* initialize libnet library to find local mac and ip addresses */
	l = libnet_init (LIBNET_LINK, config->dev, libnet_errbuf);
	if (NULL == l) {
		printf ("\n [-] libnet_init() failed: %s\n\n", libnet_errbuf);
		exit (EXIT_FAILURE);
	}

	/* fetch local mac address */
	config->macaddr = libnet_get_hwaddr (l);
	if (NULL == config->macaddr) {
		printf ("\n [-] could not fetch local mac address: %s\n\n", libnet_geterror (l));
		libnet_destroy (l);
		exit (EXIT_FAILURE);
	} else {
		snprintf (config->llmac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
				config->macaddr->ether_addr_octet[0], config->macaddr->ether_addr_octet[1],
				config->macaddr->ether_addr_octet[2], config->macaddr->ether_addr_octet[3],
				config->macaddr->ether_addr_octet[4], config->macaddr->ether_addr_octet[5]);
	}

	/* fetch local ip address */
	config->ipaddr = libnet_get_ipaddr4 (l);
	if (-1 == config->ipaddr) {
		printf ("\n [-] could not fetch local ip address: %s\n\n", libnet_geterror (l));
		libnet_destroy (l);
		exit (EXIT_FAILURE);
	} else {
		snprintf (config->llip, 16, "%s", libnet_addr2name4 (config->ipaddr, LIBNET_DONT_RESOLVE));
	}

	printf (" [+] session started at %s \n", start_time);
	printf (" [+] default configuration and cmd-line parameters loaded\n");
	printf (" [+] device: \"%s\", mode: \"%s\", port: \"%s\", scan-type: \"%s\"\n",
		config->dev, (config->mode)? "PREVENT" : "DETECT", config->a_port_name,	config->a_scan_type);

	/* start repeat loop */

	/* call sniffer module to fill up our config struct with packet fields */
	printf (" [+] calling arp-sniffer module to capture incoming arp packets\n");
	config = sniffer (config);

	printf ("\n [+] above arp packet was captured and respective fields were saved for analysis\n");
	printf (" [+] calling anamoly-detection module to perform static analysis on saved packet fields\n");

	/* call static_analysis module to perform some static checks on packet fields */
	valid = static_analysis (conf);
	if (EXIT_FAILURE == valid) {
		printf (" [+] analyzed arp packet seems to be specially-crafted. kernel might have added the"
			" poisonous SIP-SMAC entry in arp cache\n");
		if (DETECT == conf.mode) {
			printf (" [+] you need to clean up arp cache manually. delete entry for SIP (%s) - SMAC (%s)\n",
				conf.a_sip, conf.a_sha);
			printf (" [+] to automate this process, please terminate this session and restart arp-secur"
				" in PREVENT mode, i.e with -P switch\n");

		} else if (PREVENT == conf.mode) {
			printf (" [+] cleaning up arp cache by deleting entry for SIP (%s) - SMAC (%s)\n",
				conf.a_sip, conf.a_sha);
				cache_cleanup (conf.a_sip, conf.a_sha);
		}
	} else {
		printf (" [+] analyzed arp packet does not seem to be specially-crafted\n");

		/* check if we have already processed (and validated) the ip-mac pair... */
		if (0 < conf.queue_size) {
			printf (" [+] calling known-traffic-filter module to check if we have validated"
				" IP - MAC (%s - %s) pair earlier (queue_size: %d)\n",
				conf.a_sip, conf.a_sha, conf.queue_size);
			known_traffic_filter (start, conf.a_sip, conf.a_sha, conf.queue_size);
		} else {
			printf (" [+] no IP-MAC pairs have been validated yet (queue_size: %d)\n", conf.queue_size);
		}

		/* ...hmmm, seems to be a new mac-ip pair. let's validate it then... */
		printf (" [+] calling spoof-detection module to validate IP - MAC (%s - %s) pair\n", conf.a_sip, conf.a_sha);
		valid = spoof_detector (conf, start, end);

		if (0 == valid) {
			printf ("\n [+] try other scan types before determining the validity of the IP - MAC (%s - %s)\n",
				conf.a_sip, conf.a_sha);
			if (DETECT == conf.mode) {
				printf (" [+] for safety reasons, you need to clean up arp cache manually."
					" delete entry for (%s - %s)\n", conf.a_sip, conf.a_sha);
				printf (" [+] to automate this process from now onwards,"
					" restart arp-secur in PREVENT mode, i.e with -P switch\n");
			} else if (PREVENT == conf.mode) {
				printf (" [+] cleaning up arp cache by deleting entry for SIP (%s) - SMAC (%s)\n",
					conf.a_sip, conf.a_sha);
				cache_cleanup (conf.a_sip, conf.a_sha);
			}
		}

		/* display session summary in a system popup notification */
		if (1 == showpopup) {
			alert (conf.a_sip, conf.a_sha, valid);
		}

		/* end repeat loop */

		/* end arp-secur session */
		bcurtime = time (NULL);
		bloctime = localtime (&bcurtime);
		strftime (end_time, 24, "%d/%b/%Y %H:%M:%S", bloctime);
		printf ("\n [+] session finished at %s\n\n", end_time);

	}

	return 0;

}//main


/* EOF */
