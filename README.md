# Netcore - Tshark

<br>
<br>

## TCP Packet Capture Program
This C program uses the `pcap` library to capture and dump TCP packets from a network interface. It lists available network interfaces and captures TCP packets from the first available interface.

<br>
<br>

## Installation
**Install `libpcap`:**

On Debian-based systems (e.g., Ubuntu):
```sh
sudo apt-get update
sudo apt-get install libpcap-dev
```

Or through links:
download: https://www.tcpdump.org/release/libpcap-1.10.5.tar.xz
doc: https://www.tcpdump.org/index.html
once downloaded and ***"untar"*** 
1. `tar -xvzf libpcap-*.tar.xz`
2. `cd libpcap-1.10.5`
3. `.configure`
4. `make && sudo make install`

You'll now be able to see :
- **Libraries:** `/usr/local/lib/libpcap.so`
- **Headers:** `/usr/local/include/pcap.h`


<br>
<br>


## tutorial
Step by step capturing network packet using the *lib pcap*
https://www.tcpdump.org/pcap.html


<br>
<br>


## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Code Explanation](#code-explanation)
- [License](#license)


<br>
<br>


## Features

- Lists all available network interfaces.
- Captures and dumps only TCP packets.
- Simple and easy-to-understand code structure.


<br>
<br>


## Requirements

- A C compiler (e.g., `gcc`).
- The `libpcap` library installed on your system.


<br>
<br>


# TCP Packet Capture Program Explanation

This document provides a detailed explanation of the `main` function and the data types used in the `pcap` library for capturing TCP packets.

## Main Function Breakdown

### Variable Declarations

```c
char *dev;
pcap_if_t *alldevs;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;
struct bpf_program fp;
char filter_exp[] = "tcp";
bpf_u_int32 net;
```

- dev: A pointer to a character string that holds the name of the network device to capture packets from.
- alldevs: A pointer to a list of network devices.
- errbuf: A buffer to store error messages.
- handle: A pointer to a pcap session handle.
- fp: A structure that holds a compiled filter program.
- filter_exp: A string containing the filter expression ("tcp" in this case).
- net: Used to store the IPv4 network address (not used in this example).

## Overview
The `main.c` file is part of the Netcore - Tshark project, which captures network packets using the `libpcap` library. It lists available network interfaces and captures packets from the selected interface.

## Compilation
To compile the program, use the following command:
```bash
gcc main.c -lpcap
```
This command links the `libpcap` library necessary for packet capturing.

## Code Breakdown

1. **Includes and Function Declaration**
   ```c
   #include <stdio.h>
   #include <pcap.h>
   ```
   - The program includes the standard I/O library and the `pcap` library, which provides functions for network packet capture.

2. **Packet Handler Function**
   ```c
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
   ```
   - This function is called for each captured packet. It prints the length of the captured packet.

3. **Main Function**
   ```c
   int main(int argc, char **argv) {
       char *dev;
       pcap_if_t *alldevs;
       char errbuf[PCAP_ERRBUF_SIZE];
       pcap_t *handle;
       struct bpf_program fp;
       char filter_exp[] = "tcp";
       bpf_u_int32 net;
   ```
   - The `main` function initializes variables for device selection, error handling, and packet capturing.
   ```
   - This function is called for each captured packet. It prints the length of the captured packet.

3. **Main Function**
   ```c
   int main(int argc, char **argv) {
       char *dev;
       pcap_if_t *alldevs;
       char errbuf[PCAP_ERRBUF_SIZE];
       pcap_t *handle;
       struct bpf_program fp;
       char filter_exp[] = "tcp";
       bpf_u_int32 net;
   ```
   - The `main` function initializes variables for device selection, error handling, and packet capturing.

4. **Finding Devices**
   ```c
   if (pcap_findalldevs(&alldevs, errbuf) == -1) {
       fprintf(stderr, "Error finding devices: %s\n", errbuf);
       return 1;
   }
   ```
   - This code retrieves a list of all available network devices. If it fails, it prints an error message and exits.

5. **Selecting the Device**
   ```c
   dev = alldevs->name;
   printf("Using device: %s\n", dev);
   ```
   - The program selects the first available device and prints its name.

6. **Opening the Device**
   ```c
   handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
   if (handle == NULL) {
       fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
       return 2;
   }
   ```
   - It opens the selected device in promiscuous mode for packet capturing. If it fails, an error message is printed.

7. **Checking Link Layer Type**
   ```c
   if (pcap_datalink(handle) != DLT_EN10MB) {
       fprintf(stderr, "%s is not an Ethernet\n", dev);
       return 3;
   }
   ```
   - The code checks if the device is an Ethernet interface. If not, it exits with an error.

8. **Compiling and Applying the Filter**
   ```c
   if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
       fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return 4;
   }

   if (pcap_setfilter(handle, &fp) == -1) {
       fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
       return 5;
   }
   ```
   - The program compiles a filter expression (in this case, for TCP packets) and applies it to the capture session.

9. **Starting Packet Capture**
   ```c
   printf("\nStarting packet capture...\n");
   while (1) {
       pcap_loop(handle, 10, packet_handler, NULL);
   }
   ```
   - It starts capturing packets in an infinite loop, calling the `packet_handler` function for each captured packet.

10. **Cleanup**
    ```c
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
    ```
    - Finally, the program cleans up by freeing resources and closing the capture session.

### Summary
The `main.c` file implements a simple packet capture tool using `libpcap`. It lists network interfaces, captures TCP packets, and prints their lengths. This tool can be useful for network analysis and debugging purposes.