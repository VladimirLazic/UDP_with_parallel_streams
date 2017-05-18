#include<stdio.h>
#include<stdbool.h>
#include<stdlib.h>
#include<string.h>    //strlen

#ifdef _WIN32
#define HAVE_STRUCT_TIMESPEC
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

int NumberOfPackets = 0;

//A datagram sturcture
typedef struct Datagram
{
	char message[DEFAULT_MESSAGE_LEN];
	int datagram_id;
	bool sent;
};

struct Datagram recivedDatagrams[DEFAULT_FILE_LEN];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);
void *device_thread_function(void *params);

int main() {
	pcap_if_t *devices;						// List of network interface controllers
	pcap_if_t *device;						// Network interface controller
	unsigned int netmask;
	char error_buffer[PCAP_ERRBUF_SIZE];	// Error buffer
	char filter_exp[] = "udp";
	struct bpf_program fcode;
	pthread_t device_thread[NUM_OF_THREADS];
	int i = 0, NumberOfThreads = 0;

	//Opening device adapters
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

	//Testing print
	printf("Devices found: \n");
	for (device = devices; device; device = device->next) {
		printf("\tDevice: name - %s\n\t        description - %s\n", device->name, device->description);
	}
	printf("\n");

	for (device = devices, i = 0; device; device = device->next, i++) {
		if (pthread_create(&device_thread[i], NULL, &device_thread_function, device)) {
			printf("Error creating a thread for device: %s\n", device->name);
		}
		else {
			NumberOfThreads++;
		}
	}

	for (i = 0; i < NumberOfThreads; i++) {
		pthread_join(device_thread[i], NULL);
	}

	return 0;
}

void *device_thread_function(void *device) {
	pcap_if_t *thread_device = (pcap_if_t *)device;
	pcap_t* device_handle;					// Descriptor of capture device
	char error_buffer[PCAP_ERRBUF_SIZE];	// Error buffer
	char packet[12 + sizeof(struct Datagram)];
	int i = 0;

	// Open the capture device
	if ((device_handle = pcap_open_live(thread_device->name,
		65536,
		0,
		2000,
		error_buffer
		)) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", thread_device->name);
		return -1;
	}

	pcap_loop(device_handle, 0, packet_handler, NULL);
}


void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data) {
	pthread_mutex_lock(&mutex);
	struct Datagram temp;
	// Retrieve position of ethernet_header
	ethernet_header* eh;
	eh = (ethernet_header*)packet_data;

	// Check the type of next protocol in packet
	if (ntohs(eh->type) == 0x800)	// Ipv4
	{
		ip_header* ih;
		ih = (ip_header*)(packet_data + sizeof(ethernet_header));

		if (ih->next_protocol == 17) // UDP
		{
			//memset(&temp, &packet_data, sizeof(struct Datagram));
		}
	}

	pthread_mutex_unlock(&mutex);
}
