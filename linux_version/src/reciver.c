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
char *cancelation = "";

void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);
void *device_thread_function(void *params);
void save_datagrams_to_file();

void print_recived_datagrams() {
	int i = 0;
	for (int i = 0; i < DEFAULT_FILE_LEN; i++) {
		if (recivedDatagrams[i].datagram_id == -1) {
			//printf("Missing!\n");
		}
		else {
			printf("%s\n", recivedDatagrams[i].message);
		}
	}
}

int main() {
	pcap_if_t *devices;						// List of network interface controllers
	pcap_if_t *device;						// Network interface controller
	unsigned int netmask;
	char error_buffer[PCAP_ERRBUF_SIZE];	// Error buffer
	char filter_exp[] = "udp and ip 192.168.1.7";
	struct bpf_program fcode;
	pthread_t device_thread[NUM_OF_THREADS] , *device_threads , cancel;
	int i = 0, NumberOfThreads = 0;
	unsigned char working_intefaces = 0;
	unsigned char thread;

	//Initializing datagrams
	for (i = 0; i < DEFAULT_FILE_LEN; i++) {
		recivedDatagrams[i].datagram_id = -1;
		strcpy(recivedDatagrams[i].message, "");
		recivedDatagrams[i].sent = false;
	}

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

		print_recived_datagrams();
		save_datagrams_to_file();
    free(device_threads);
		return 0;
}

void *cancelation_thread(void *param) {
	while(1) {
		pthread_mutex_lock(&mutex);
		printf("Press q to exit: ");
		scanf("%s", cancelation);
		if(strcmp(cancelation , "q") == 0) {
			print_recived_datagrams();
			save_datagrams_to_file();
			return 0;
		}
		pthread_mutex_unlock(&mutex);
	}
}
void *device_thread_function(void *device) {
	pcap_if_t *thread_device = (pcap_if_t *)device;
	pcap_t* device_handle;					// Descriptor of capture device
	char error_buffer[PCAP_ERRBUF_SIZE];	// Error buffer
	char packet[12 + sizeof(struct Datagram)];
	unsigned int netmask;
	char filter_exp[] = "udp and src 192.168.1.3";
	struct bpf_program fcode;
	int i = 0;

	// Open the capture device
	if ((device_handle = pcap_open_live(thread_device->name,
		65536,
		1,
		2000,
		error_buffer
		)) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", thread_device->name);
		return;
	}
#ifdef _WIN32
	if (thread_device->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(thread_device->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;
#else
	if (!thread_device->addresses->netmask)
		netmask = 0;
	else
		netmask = ((struct sockaddr_in *)(thread_device->addresses->netmask))->sin_addr.s_addr;
#endif

	// Compile the filter
	if (pcap_compile(device_handle, &fcode, filter_exp, 1, netmask) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return;
	}
	// Set the filter
	if (pcap_setfilter(device_handle, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return;
	}


	printf("\nListening on %s...\n", thread_device->description);

	pcap_loop(device_handle, 35, packet_handler, NULL);
}


void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data) {
	pthread_mutex_lock(&mutex);
	struct Datagram temp;
	ethernet_header* eh;
	char *data[sizeof(struct Datagram)];
	eh = (ethernet_header*)packet_data;
	unsigned char ipv4_addr_dst[4];

	ipv4_addr_dst[0] = (char)192;
	ipv4_addr_dst[1] = (char)168;
	ipv4_addr_dst[2] = (char)1;
	ipv4_addr_dst[3] = (char)3;

	// Check the type of next protocol in packet
	if (ntohs(eh->type) == 0x800)	// Ipv4
	{
		ip_header* ih;
		ih = (ip_header*)(packet_data + sizeof(ethernet_header));

		if (ih->next_protocol == 17) // UDP
		{
			if (memcmp(ipv4_addr_dst, ih->src_addr, 4 * sizeof(char)) == 0 && memcmp(ipv4_addr_dst, ih->dst_addr, 4 * sizeof(char)) == 0) {
				//printf("Detected your packet %s\n" , packet_data + sizeof(ethernet_header) + sizeof(ip_header) + sizeof(udp_header));
				//printf("Packet len: %d\t Cap len: %d\n", packet_header->len , packet_header->caplen);
				memcpy(&temp, packet_data + sizeof(ethernet_header) + sizeof(ip_header) + sizeof(udp_header), sizeof(struct Datagram));
				memcpy(&recivedDatagrams[temp.datagram_id], &temp, sizeof(struct Datagram));
			}
		}
	}
	pthread_mutex_unlock(&mutex);
}

void save_datagrams_to_file() {
	int i = 0;
	FILE *fp = fopen("recivedDatagrams.txt" , "w");
	for(i = 0; i < DEFAULT_FILE_LEN; i++) {
		if(recivedDatagrams[i].datagram_id != -1)
			fprintf(fp , "%s", recivedDatagrams[i].message);
	}
	fclose(fp);
}
