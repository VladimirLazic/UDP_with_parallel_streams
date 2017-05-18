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

//A datagram sturcture
typedef struct Datagram
{
	char message[DEFAULT_MESSAGE_LEN];
	int datagram_id;
};

//An array of datagrams to be sent
struct Datagram datagrams[DEFAULT_FILE_LEN];

void fill_datagrams(char* file_name) {
	FILE *file;
	char line[DEFAULT_MESSAGE_LEN];
	int i = 0;
	


	for (i = 0; i < DEFAULT_FILE_LEN; i++) {
		strcpy(datagrams[i].message, "");
		datagrams[i].datagram_id = -1;
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
	}
}
void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);
void *device_thread_function(void *params);


int main(int argc, char **argv) {
	pcap_if_t *devices;						// List of network interface controllers
	pcap_if_t *device;						// Network interface controller
	unsigned int netmask;
	char error_buffer[PCAP_ERRBUF_SIZE];	// Error buffer
	char filter_exp[] = "udp";
	struct bpf_program fcode;
	pthread_t device_thread[NUM_OF_THREADS];
	int i = 0;

	//Filling datagrams
	printf("File to be loaded: %s\n", argv[1]);
	fill_datagrams(argv[1]);

	//Printing out datagrams
	for (i = 0; i < DEFAULT_FILE_LEN; i++) {
		if (datagrams[i].datagram_id != -1)
			printf("%s", datagrams[i].message);
	}
	printf("\n\n\n");

	//Opening device adapters
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

	for (device = devices , i = 0; device; device = device->next , i++) {
		if (pthread_create(&device_thread[i], NULL, &device_thread_function, device)) {
			printf("Error creating a thread for device: %s\n", device->name);
		}
		pthread_join(device_thread[i], NULL);
	}



	return 0;	
}

void *device_thread_function(void *device) {
	pcap_if_t *thread_device = (pcap_if_t *)device;
	pcap_t* device_handle;					// Descriptor of capture device
	char error_buffer[PCAP_ERRBUF_SIZE];	// Error buffer

	printf("Thread for device: %s\n", thread_device->name);

	// Open the capture device
	if ((device_handle = pcap_open_live(thread_device->name,
		65536,						
		0,							
		2000,						
		error_buffer				
		)) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by libpcap/WinPcap\n", thread_device->name);
		//pcap_freealldevs(thread_device);
		return -1;
	}

	
}