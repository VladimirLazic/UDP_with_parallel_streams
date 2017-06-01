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

#include"headers.h"

//An array of datagrams to be sent
struct Datagram datagrams[DEFAULT_FILE_LEN];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


void packet_handler(unsigned char *param, const struct pcap_pkthdr *packet_header, const unsigned char *packet_data);
void *device_thread_function(void *params);


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
