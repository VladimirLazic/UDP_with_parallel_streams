#include<stdio.h>
#include<stdbool.h>
#include<stdlib.h>
#include<string.h>    //strlen

#ifdef _WIN32
#define HAVE_STRUCT_TIMESPEC
#pragma comment(lib, "Ws2_32.lib")
#endif // _W

#include<pthread.h>
#include<pcap.h>
#include"protocol_headers.h"

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#define DEFAULT_PORT   27015
#define DEFAULT_FILE_LEN 1024
#define DEFAULT_MESSAGE_LEN 512
#define BUF_LEN 512
#define NUM_OF_THREADS 5
#define ALIGN 520

int NumberOfPackets = 0;

//A datagram sturcture
typedef struct Datagram
{
	char message[DEFAULT_MESSAGE_LEN];
	int datagram_id;
	bool sent;
};


//An array of datagrams to be sent
struct Datagram datagrams[DEFAULT_FILE_LEN];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);
void *device_thread_function(void *params);
void  create_packet_header(unsigned char *datagram , struct Datagram data);
unsigned short calculate_ip_checksum(unsigned char *ip_hdr);
unsigned short BytesTo16(unsigned char X, unsigned char Y);
unsigned short calculate_udp_checksum(udp_header *udp, ip_header *ip , struct Datagram data);

void fill_datagrams(char* file_name) {
	FILE *file;
	char line[DEFAULT_MESSAGE_LEN];
	int i = 0;


	//Annulling datagrams and datagram helper
	for (i = 0; i < DEFAULT_FILE_LEN; i++) {
		strcpy(datagrams[i].message, "");
		datagrams[i].datagram_id = -1;
		datagrams[i].sent = false;
	}

	file = fopen(file_name, "r");

	if (file == NULL) {
		exit(EXIT_FAILURE);
	}

	i = 0;
	while (fgets(line, DEFAULT_MESSAGE_LEN, file) != NULL) {
		if (i == DEFAULT_FILE_LEN) {
			perror("File size is higher than alowed\n");
			exit(EXIT_FAILURE);
		}

		datagrams[i].datagram_id = i;
		strcpy(datagrams[i].message, line);
		i++;
		NumberOfPackets = i;
	}

}

int main(int argc, char **argv) {
	pcap_if_t *devices , *selected_devices;						// List of network interface controllers
	pcap_if_t *device;						// Network interface controller
	unsigned int netmask;
	char error_buffer[PCAP_ERRBUF_SIZE];	// Error buffer
	char filter_exp[] = "udp";
	struct bpf_program fcode;
	pthread_t device_thread[NUM_OF_THREADS] , *device_threads;
	int i = 0 , NumberOfThreads = 0 , device_number[2];
	unsigned char working_intefaces = 0;
	unsigned char thread;

	//Filling datagrams
	printf("File to be loaded: %s\n", argv[1]);
	fill_datagrams(argv[1]);

	//Printing out datagrams
	for (i = 0; i < DEFAULT_FILE_LEN; i++) {
		if (datagrams[i].datagram_id != -1)
			printf("%d: %s", datagrams[i].datagram_id , datagrams[i].message);
	}
	printf("\n\n\n");

	//Opening device adapters
	if (pcap_findalldevs(&devices, error_buffer) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        exit(-1);
    }
    for (device = devices; device; device = device->next) {
        /**<We want all network interfaces that aren't loop back and aren't "any" (for linux any captures usb and lo)*/
        if (device->flags && !(device->flags & PCAP_IF_LOOPBACK) &&
            (device->flags & PCAP_IF_RUNNING && device->flags & PCAP_IF_UP) &&
            strcasecmp(device->name, "any")) {
            working_intefaces++;
        }
    }
    if (!working_intefaces) {
        printf("No running network interfaces were found exiting\n");
        exit(-2);
    }
    device_threads = malloc(sizeof(pthread_t) * working_intefaces);
    working_intefaces = 0;
    for (device = devices; device; device = device->next) {
        if (device->flags && !(device->flags & PCAP_IF_LOOPBACK) &&
            (device->flags & PCAP_IF_RUNNING && device->flags & PCAP_IF_UP) &&
            strcasecmp(device->name, "any")) {
            if (pthread_create(&device_threads[working_intefaces], NULL, &device_thread_function, device)) {
                printf("Couldn't create thread for %s\n", device->name);
                exit(-3);
            }
            working_intefaces++;
        }
    }
    for (thread = 0; thread < working_intefaces; thread++) {
        pthread_join(device_threads[thread], NULL);
    }
    free(device_threads);
		return 0;
}

void *device_thread_function(void *device) {
	pcap_if_t *thread_device = (pcap_if_t *)device;
	pcap_t* device_handle;					// Descriptor of capture device
	char error_buffer[PCAP_ERRBUF_SIZE];	// Error buffer
	unsigned char packet[sizeof(ethernet_header) + sizeof(ip_header) + sizeof(udp_header) + sizeof(struct Datagram)];
	int i = 0;


	printf("Thread belongs to: %s\n" , thread_device->name);
	// Open the capture device
	if ((device_handle = pcap_open_live(thread_device->name,
		65536,
		0,
		2000,
		error_buffer
		)) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", thread_device->name);
		return;
	}


	for (i = 0; i < NumberOfPackets; i++) {
		pthread_mutex_lock(&mutex);
		if (!datagrams[i].sent) {
			//Create a udp datagram
			create_packet_header(packet , datagrams[i]);
			memcpy((packet + sizeof(ethernet_header) + sizeof(ip_header) + sizeof(udp_header)), &datagrams[i], sizeof(struct Datagram));

			//Send a usp datagram
			if (pcap_sendpacket(device_handle, packet, sizeof(ethernet_header) + sizeof(ip_header) + sizeof(udp_header) + sizeof(struct Datagram)) != 0) {
				printf("Error sending packet id: %d by thread %s\n", datagrams[i].datagram_id , thread_device->name);
			} else {
				printf("Success sending packet id: %d by thread: %s\n", datagrams[i].datagram_id , thread_device->name);
				datagrams[i].sent = true;
			}
		}
		pthread_mutex_unlock(&mutex);
	}
}

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
