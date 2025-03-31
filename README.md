# Netcore - Tshark

<br>
<br>

## Installation
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