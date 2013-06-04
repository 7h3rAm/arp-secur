/*
 * anamoly-detector.c
 *
 * performs some static analysis on ethernet_arp header fields
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


int
static_analysis (struct configuration conf) {

	int c;
	char *str;
	char *bcast_mac = "ff:ff:ff:ff:ff:ff";
	char *null_mac = "00:00:00:00:00:00";

	struct configuration *config = &conf;

	/* if its an arp-request... */
	if (ARP_OPCODE_REQUEST == config->oper) {
		printf ("\n [*] found an incoming arp request packet\n");

		/* smac should not be 00:00:00:00:00:00 */
		if (0 == strncmp (config->e_smac, null_mac, 17)) {
			printf (" [*] found SMAC to be NULL (%s). crafted arp-request. returning -1\n\n", config->e_smac);
			return EXIT_FAILURE;
		} else {
			printf (" [*] found SMAC to be (%s), i.e not null\n", config->e_smac);
		}

		/* smac should not be ff:ff:ff:ff:ff:ff */
		if (0 == strncmp (config->e_smac, bcast_mac, 17)) {
			printf (" [*] found SMAC to be L2 bcast (%s). crafted arp-request. returning -1\n\n", config->e_smac);
			return EXIT_FAILURE;
		} else {
			printf (" [*] found SMAC to be (%s), i.e non-broadcast\n", config->e_smac);
		}

		/* smac and dmac should not match */
		if (0 == strncmp (config->e_smac, config->e_dmac, 17)) {
			printf (" [*] found SMAC and DMAC to be (%s). crafted arp-request. returning -1\n\n",
				config->e_smac, config->e_dmac);
			return EXIT_FAILURE;
		} else {
			printf (" [*] found SMAC (%s) and DMAC (%s) to be different\n", config->e_smac, config->e_dmac);
		}

		/* check if smac and sha match */
		if (0 == strncmp (config->e_smac, config->a_sha, 17)) {
			printf (" [*] found SMAC and SHA to be same (%s)\n", config->a_sha);
		} else {
			printf (" [*] found SMAC (%s) and SHA (%s). crafted arp-request. returning -1\n\n",
				config->e_smac, config->a_sha);
			return EXIT_FAILURE;
		}

		/* dmac should preferably be ff:ff:ff:ff:ff:ff */
		if (0 == strncmp (config->e_dmac, bcast_mac, 17)) {
			printf (" [*] found DMAC to be L2 bcast (%s)\n", config->e_dmac);
		} else {
			printf (" [*] found DMAC to be (%s), i.e non-broadcast... ignored\n", config->e_dmac);
		}

		/* dha should preferably be 00:00:00:00:00:00 */
		if (0 == strncmp (config->a_dha, null_mac, 17)) {
			printf (" [*] found DHA to be NULL (%s)\n", config->a_dha);
		} else {
			printf (" [*] found DHA to be (%s), i.e not null... ignored\n", config->a_dha);
		}

		/* sip and dip should not match */
		if (0 == strncmp (config->a_sip, config->a_dip, 15)) {
			printf (" [*] found SIP and DIP to be (%s). crafted arp-request. returning -1\n\n", config->a_sip);
			return EXIT_FAILURE;
		} else {
			printf (" [*] found SIP (%s) and DIP (%s) to be different\n", config->a_sip, config->a_dip);
		}

	} else if (ARP_OPCODE_REPLY == config->oper) {
		printf ("\n [*] found an incoming arp reply packet\n");

		/* smac should not be 00:00:00:00:00:00 */
		if (0 == strncmp (config->e_smac, null_mac, 17)) {
			printf (" [*] found SMAC to be NULL (%s). crafted arp-reply. returning -1\n\n", config->e_smac);
			return EXIT_FAILURE;
		} else {
			printf (" [*] found SMAC to be (%s), i.e not null\n", config->e_smac);
		}

		/* smac should not be ff:ff:ff:ff:ff:ff */
		if (0 == strncmp (config->e_smac, bcast_mac, 17)) {
			printf (" [*] found SMAC to be L2 bcast (%s). crafted arp-reply. returning -1\n\n", config->e_smac);
			return EXIT_FAILURE;
		} else {
			printf (" [*] found SMAC to be (%s), i.e non-broadcast\n", config->e_smac);
		}

		/* smac and sha should match */
		if (0 == strncmp (config->e_smac, config->a_sha, 17)) {
			printf (" [*] found SMAC and SHA to be same (%s)\n", config->a_sha);
		} else {
			printf (" [*] found SMAC (%s) and SHA (%s). crafted arp-reply. returning -1\n\n",
				config->e_smac, config->a_sha);
			return EXIT_FAILURE;
		}

		/* smac and dmac should not match */
		if (0 == strncmp (config->e_smac, config->e_dmac, 17)) {
			printf (" [*] found SMAC and DMAC to be (%s). crafted arp-reply. returning -1\n\n",
				config->e_smac, config->e_dmac);
			return EXIT_FAILURE;
		} else {
			printf (" [*] found SMAC (%s) and DMAC (%s) to be different\n", config->e_smac, config->e_dmac);
		}

		/* dmac should not be ff:ff:ff:ff:ff:ff */
		if (0 == strncmp (config->e_dmac, bcast_mac, 17)) {
			printf (" [*] found DMAC to be L2 bcast (%s). crafted arp-reply. returning -1\n\n", config->e_dmac);
			return EXIT_FAILURE;
		} else {
			printf (" [*] found DMAC to be (%s), i.e non-broadcast\n", config->e_dmac);
		}

		/* dmac and dha should match */
		if (0 == strncmp (config->e_dmac, config->a_dha, 17)) {
			printf (" [*] found DMAC and DHA to be same (%s)\n", config->a_dha);
		} else {
			printf (" [*] found DMAC (%s) and DHA (%s). crafted arp-reply. returning -1\n\n",
				config->e_dmac, config->a_dha);
			return EXIT_FAILURE;
		}

		/* sip and dip should not match */
		if (0 == strncmp (config->a_sip, config->a_dip, 15)) {
			printf (" [*] found SIP and DIP to be (%s). crafted arp-reply. returning -1\n\n", config->a_sip);
			return EXIT_FAILURE;
		} else {
			printf (" [*] found SIP (%s) and DIP (%s) to be different\n", config->a_sip, config->a_dip);
		}
	}
	printf ("\n");

	return EXIT_SUCCESS;

}//sniffer


/* EOF */
