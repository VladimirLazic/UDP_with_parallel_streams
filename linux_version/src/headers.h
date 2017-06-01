//Function declarations for all important header functions
/**
  Function that creates a packet header
*/
void  create_packet_header(unsigned char *datagram , struct Datagram data);

/**
  Function for calculation of ip checksum
*/
unsigned short calculate_ip_checksum(unsigned char *ip_hdr);
/**
  A help function that converts bytes to hex. Used in calculating check sums
*/
unsigned short BytesTo16(unsigned char X, unsigned char Y);

/**
  Function for calculation of udp checksum
*/
unsigned short calculate_udp_checksum(udp_header *udp, ip_header *ip , struct Datagram data);
