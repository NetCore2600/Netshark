/* Netcore - Tshark
   Jonathan Todnelier
   
   To compile:
   >gcc main.c -lpcap

   Looks for an interface, and lists the network ip
   and mask associated with that interface.
   see: https://yuba.stanford.edu/~casado/pcap/section1.html
*/

#include <stdio.h>
#include <pcap.h>

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
    // Print the timestamp
    printf("Timestamp: %ld.%06ld\n", header->ts.tv_sec, header->ts.tv_usec);
    
    // Print the captured and actual lengths
    printf("Captured Length: [%d]\n", header->len);
    printf("Actual Length: [%d]\n", header->caplen);
    
    // Print packet data in hexadecimal format
    printf("Packet Data:\n");
    for (int i = 0; i < header->caplen; i++) 
    {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) 
        {
            printf("\n");
        }
    }
    printf("\n\n");
}

int main(int argc, char **argv) {
    char *dev;
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // 1. Get the list of devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Use the first device
    dev = alldevs->name;
    // while (alldevs != NULL) {
    //     printf("%s\n", alldevs->name);
    //     alldevs = alldevs->next;
    // }
    // return 0;
    printf("Using device: %s\n", dev);

    // Open the session in promiscuous mode
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    // Check the link layer type
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        return 3;
    }

    // Compile and apply the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 4;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 5;
    }

    // Now we can set our callback function
    printf("\nStarting packet capture...\n");

    while (1)
    {
        pcap_loop(handle, 10, packet_handler, NULL);
    }
    

    // Clean up
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
