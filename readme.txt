Sokratis Siganos - 2019030097

The following c tool uses the pcap library to implement 2 functionalities:

1. Read a .pcap file:
    ex. ./pcap_ex -r pcap_file.pcap

2. Monitor the packet traffic live from a network Interface:
    ex. ./pcap_ex -i en0 -f "port 443"

For both of these implementations, structs such as ip, ip6_hdr, tcp_hdr, udp_hdr
as well as functions as ntohs, inet_ntop were used from the inet library.

For reading the capture file, the tool reads the savefile's name from the terminal, and foreach packet
it inside of it, it updates the statistics of the proccess and it prints in the terminal info for any packet that
contains a TCP/UDP protocol. This proccess works for IPv4/IPv6 protocols. After reading all available packets, the proccess
is completed after printing in the terminal the statistics of the savefile, such as toatal network/udp/tcp flows, total packets,
total tcp/udp packets, total bytes of tcp/udp packets.

For the 2nd functionality, the tool starts a monitoring proccess, which captures all the packet traffic from 
a given network interface. The capure stops after reading MAX_PACKETS(2000) from the traffic. Each time it 
captures a TCP/UDP packet, it saves the packet's information inside a logfile. In this proccess, by adding the -f argument,
the displayed filters inside the logfile can be filtered by a specific port number and only packets with src/dst 
ports equal to this number are written inside the logfile.After the proccess is finished, the statistics of 
the proccess, as described above, are printed in the terminal.

Sources: https://linux.die.net/man/3/pcap
    https://www.tcpdump.org/