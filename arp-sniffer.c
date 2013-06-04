/*
 * arp-sniffer.c
 *
 * sniffer for capturing ARP packets on an Ethernet network
 * version 0.3 (2011-04-09)
 * 
 ****************************************************************************
 *
 * Code Comments
 *
 ****************************************************************************
 *
 */


#include "config.h"
#include "pcap-utils.h"						/* routines to print packet contents */


int local = 0;							/* flag to check if the captured packet is for localhst */
u_long lip;							/* used to copy addresses */
u_int16_t oper;
char e_smac[18], e_dmac[18],
	a_sha[18], a_sip[16],
	a_dha[18], a_dip[16];
char *llip;							/* stores local ip to match against dip in received ARP packet */
u_char *arp_packet;						/* contents of incoming ARP packet */
u_int caplen, length;						/* stores captured packet length and offwire length */

/* parse the captured packet */
void
parse_packet (u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

	int i;
	char destip[16];
	u_int16_t type;

	caplen = pkthdr->caplen;				/* length of portion present from bpf  */
	length = pkthdr->len;					/* length of this packet off the wire  */

	const struct ethernet_hdr *ethernet; 			/* ethernet header */
	const struct arp_hdr *arp; 				/* arp header */

	ethernet = (struct ethernet_hdr *) packet;		/* point to the Ethernet header */
	arp = (struct arp_hdr *)(packet+14);			/* point to the ARP header */

	type = ntohs (ethernet->ether_type);

	/* we want an arp packet... */
	if (ETHERTYPE_ARP == type) {

		snprintf (destip, 16, "%d.%d.%d.%d",
				arp->arp_dip[0], arp->arp_dip[1], arp->arp_dip[2], arp->arp_dip[3]);

		/* check if it is an incoming packet, ie local ip should match destip of captured packet */
		if (!(strncmp (destip, llip, sizeof (destip)))) {
			local = 1;
			arp_packet = packet;

			/* load ethernet header fields into our global vars */
			snprintf (e_smac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
					ethernet->ether_smac[0], ethernet->ether_smac[1], ethernet->ether_smac[2],
					ethernet->ether_smac[3], ethernet->ether_smac[4], ethernet->ether_smac[5]);

			snprintf (e_dmac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
					ethernet->ether_dmac[0], ethernet->ether_dmac[1], ethernet->ether_dmac[2],
					ethernet->ether_dmac[3], ethernet->ether_dmac[4], ethernet->ether_dmac[5]);

			oper = ntohs (arp->arp_oper);

			snprintf (a_sha, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
					arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
					arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);

			snprintf (a_sip, 16, "%d.%d.%d.%d",
					arp->arp_sip[0], arp->arp_sip[1], arp->arp_sip[2], arp->arp_sip[3]);

			snprintf (a_dha, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
					arp->arp_dha[0], arp->arp_dha[1], arp->arp_dha[2],
					arp->arp_dha[3], arp->arp_dha[4], arp->arp_dha[5]);

			snprintf (a_dip, 16, "%d.%d.%d.%d",
					arp->arp_dip[0], arp->arp_dip[1],
					arp->arp_dip[2], arp->arp_dip[3]);
		} else {
			local = 0;
			return;
		}
	}

	return;

}//parse_packet


struct configuration 
*sniffer (struct configuration *config) {

	char errbuf[PCAP_ERRBUF_SIZE];				/* error buffer */
	pcap_t *handle;						/* packet capture handle */
	struct pcap_stat *ps;					/* struct to hold pcap session stats */

	char *filter_exp = "arp";				/* capture filter */
	struct bpf_program fp;					/* compiled filter program */
	int num_packets = CAPLEN;				/* max bytes to capture */

	/* get network id and mask associated with capture device */
	if (pcap_lookupnet (config->dev, &config->net, &config->mask, errbuf) == -1) {
		fprintf (stderr, "\n [-] could not get network id and mask for device %s\n\n", errbuf);
		exit (EXIT_FAILURE);
	}

	/* open capture device */
	handle = pcap_open_live (config->dev, SNAPLEN, PROMISC, 0, errbuf);
	if (handle == NULL) {
		fprintf (stderr, "\n [-] could not open device %s\n\n", errbuf);
		exit (EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device */
	if (pcap_datalink (handle) != DLT_EN10MB) {
		fprintf (stderr, "\n [-] %s is not on an Ethernet network\n\n", config->dev);
		exit (EXIT_FAILURE);
	}

	/* compile the capture filter expression */
	if (pcap_compile (handle, &fp, filter_exp, 0, config->net) == -1) {
		fprintf (stderr, "\n [-] could not parse filter %s: %s\n\n", filter_exp, pcap_geterr (handle));
		exit (EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter (handle, &fp) == -1) {
		fprintf (stderr, "\n [-] could not install filter %s: %s\n\n", filter_exp, pcap_geterr (handle));
		exit (EXIT_FAILURE);
	}

	/* read our lip from config struct into a global variable for filtering traffic in parse_packet */
	llip = config->llip;

	/* print capture info and start sniffing */
	printf ("\n [*] capture size is set to %04d. promisc flag is %s\n", SNAPLEN, (PROMISC)? "SET" : "UNSET");
	if (pcap_datalink (handle) == DLT_EN10MB) {
		printf (" [*] sniffing on device \"%s\" [DLT_EN10MB] with capture filter \"%s\"\n\n", config->dev, filter_exp);
	}

	/* now we can set our callback function */
	while (0 == local) {
		//pcap_loop (handle, CAPLEN, parse_packet, NULL);
		pcap_dispatch (handle, 1, parse_packet, NULL);
	}

	/* fill-up the config structure with values from captured packet */
	strncpy (config->e_smac, e_smac, sizeof (e_smac));
	strncpy (config->e_dmac, e_dmac, sizeof (e_dmac));
	config->oper = oper;
	strncpy (config->a_sha, a_sha, sizeof (a_sha));
	strncpy (config->a_sip, a_sip, sizeof (a_sip));
	strncpy (config->a_dha, a_dha, sizeof (a_dha));
	strncpy (config->a_dip, a_dip, sizeof (a_dip));

	/* display captured packet's content */
	if (ARP_OPCODE_REQUEST == config->oper) {
		printf (" { ETH: %s -> %s } { ARP: arp-request who-has %s tell %s }\n",
			config->e_smac, config->e_dmac, config->a_dip, config->a_sip);
	} else if (ARP_OPCODE_REPLY == config->oper) {
		printf (" { ETH: %s -> %s } { ARP: arp-reply %s is-at %s }\n",
			config->e_smac, config->e_dmac, config->a_sip, config->a_sha);
	}

	if (1 == config->verbose) {
		printpayload (arp_packet, caplen);
	}

	/* cleanup */
	pcap_freecode (&fp);
	pcap_close (handle);

	return config;

}//sniffer


/* EOF */
