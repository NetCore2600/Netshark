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

int main(int argc, char **argv)
{
	char *dev = argv[1];

	printf("Device: %s\n", dev);
	return(0);
}