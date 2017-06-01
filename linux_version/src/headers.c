#include "headers.h"

void create_packet_header(unsigned char *datagram , struct Datagram data) {
	udp_header *udp_hdr = (udp_header *) malloc(sizeof(udp_header));
	ip_header *ip_hdr = (ip_header *) malloc(sizeof(ip_header));
	ethernet_header *eth_hdr = (ethernet_header *) malloc(sizeof(ethernet_header));
	unsigned char ipv4_addr_dst[4];
	unsigned char eth_addr_src[6];
	unsigned char ip_helper[sizeof(ip_header) - sizeof(unsigned short)];

	//Initializing
	memset(udp_hdr, 0, sizeof(udp_header));
	memset(ip_hdr, 0, sizeof(ip_header));
	memset(eth_hdr, 0, sizeof(ethernet_header));

	//Creating a udp header
	udp_hdr->src_port = htons(8888);
	udp_hdr->dest_port = htons(8888);
	udp_hdr->datagram_length = htons(sizeof(udp_header) + sizeof(struct Datagram));

	//Creating a ip header
	ip_hdr->next_protocol = 17;		//0x11 UDP protocol
	ip_hdr->dst_addr[0] = 192;
	ip_hdr->dst_addr[1] = 168;
	ip_hdr->dst_addr[2] = 1;
	ip_hdr->dst_addr[3] = 3;

	ip_hdr->src_addr[0] = 192;
	ip_hdr->src_addr[1] = 168;
	ip_hdr->src_addr[2] = 1;
	ip_hdr->src_addr[3] = 3;

	ip_hdr->version = 4;
	ip_hdr->ttl = 128;
	ip_hdr->header_length = 20 / 4;
	ip_hdr->length = htons(sizeof(ip_header) + sizeof(udp_header) + sizeof(struct Datagram));

	memcpy(ip_helper, ip_hdr, 22);

	//Creating ip and udp headers
	udp_hdr->checksum = calculate_udp_checksum(udp_hdr, ip_hdr , data);
	ip_hdr->checksum = calculate_ip_checksum(ip_helper);


	//Creating a ethernet header
	eth_hdr->dest_address[0] = 0x90;
	eth_hdr->dest_address[1] = 0xe6;
	eth_hdr->dest_address[2] = 0xba;
	eth_hdr->dest_address[3] = 0xaa;
	eth_hdr->dest_address[4] = 0xfa;
	eth_hdr->dest_address[5] = 0xdb;


	eth_hdr->src_address[0] = 0x14;
	eth_hdr->src_address[1] = 0x2d;
	eth_hdr->src_address[2] = 0x27;
	eth_hdr->src_address[3] = 0xf3;
	eth_hdr->src_address[4] = 0x94;
	eth_hdr->src_address[5] = 0x0b;
	eth_hdr->type = htons(0x800);


	memcpy(datagram, eth_hdr, sizeof(ethernet_header));
	memcpy(datagram + sizeof(ethernet_header), ip_hdr, sizeof(ip_header));
	memcpy(datagram + sizeof(ethernet_header) + sizeof(ip_header) - 4, udp_hdr, sizeof(udp_header));

	udp_hdr = NULL;
	ip_hdr = NULL;
	eth_hdr = NULL;

	free(udp_hdr);
	free(ip_hdr);
	free(eth_hdr);
}

unsigned short calculate_ip_checksum(unsigned char *ip_hdr) {
	unsigned short CheckSum = 0;
	for (int i = 0; i<22; i += 2)
	{
		unsigned short Tmp = BytesTo16(ip_hdr[i], ip_hdr[i + 1]);
		unsigned short Difference = 65535 - CheckSum;
		CheckSum += Tmp;
		if (Tmp > Difference) { CheckSum += 1; }
	}
	CheckSum = ~CheckSum;
	return htons(CheckSum);
}

unsigned short calculate_udp_checksum(udp_header *udp, ip_header *ip , struct Datagram data) {
	unsigned short CheckSum = 0;

	//length of pseudo_header = Data length + 8 bytes UDP header + Two 4 byte IP's + 1 byte protocol
	unsigned short pseudo_length = sizeof(struct Datagram) + 8 + 9;

	//If bytes are not an even number, add an extra.
	pseudo_length += pseudo_length % 2;

	// This is just UDP + Data length.
	unsigned short length = sizeof(struct Datagram) + 8;

	//Init
	unsigned char* pseudo_header = (unsigned char*) malloc(pseudo_length * sizeof(unsigned char));
	for (int i = 0; i < pseudo_length; i++) {
		pseudo_header[i] = 0x00;
	}

	// Protocol
	memcpy(pseudo_header, &(ip->next_protocol), 1);

	// Source and Dest IP
	memcpy(pseudo_header + 1, &(ip->src_addr), 4);
	memcpy(pseudo_header + 5, &(ip->dst_addr), 4);

	// length is not network byte order yet
	length = htons(length);

	//Included twice
	memcpy(pseudo_header + 9, (void*)&length, 2);
	memcpy(pseudo_header + 11, (void*)&length, 2);

	//Source Port
	memcpy(pseudo_header + 13, &(udp->src_port), 2);

	//Dest Port
	memcpy(pseudo_header + 15, &(udp->dest_port), 2);
	memcpy(pseudo_header + 17, &data, sizeof(struct Datagram));


	for (int i = 0; i < pseudo_length; i += 2)
	{
		unsigned short Tmp = BytesTo16(pseudo_header[i], pseudo_header[i + 1]);
		unsigned short Difference = 65535 - CheckSum;
		CheckSum += Tmp;
		if (Tmp > Difference) { CheckSum += 1; }
	}
	CheckSum = ~CheckSum; //One's complement

	pseudo_header = NULL;
	free(pseudo_header);

	return CheckSum;
}

unsigned short BytesTo16(unsigned char X, unsigned char Y) {
	unsigned short Tmp = X;
	Tmp = Tmp << 8;
	Tmp = Tmp | Y;
	return Tmp;
}
