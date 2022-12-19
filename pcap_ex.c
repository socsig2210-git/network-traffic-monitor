#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define MAX_SNAPLEN 65535 // Used in pcap_open_live
#define MAX_PACKETS 2000  // Max packets per capture
#define LOG_FILE "logfile.txt"
#define TIMEOUT 500

#define MAX_FLOWS 50000 // Max size of flows array

// flow struct (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol)
typedef struct flow
{
    // ip is either v4 or v6
    union
    {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    } src_ip;
    union
    {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    } dst_ip;
    uint src_port;
    uint dst_port;
    uint8_t protocol;
} flow;
struct flow flows[MAX_FLOWS];

// Statistics as specified
typedef struct statistics
{
    int network_flows_cnt;
    int tcp_flows_cnt;
    int udp_flows_cnt;
    int pckt_cnt;
    int tcp_cnt;
    int udp_cnt;
    int tcp_b_cnt;
    int udp_b_cnt;
} statistics;
struct statistics *stats; // Initialize stats in global scope

FILE *stream = NULL; // stream init
int port_filter = 0; // port filter default value 0, same for unused filter

int capture(char *);
int read_capture_file(char *, char *);
void packet_handle(u_char *, const struct pcap_pkthdr *, const u_char *);

struct statistics *statistics_init();
void usage();
void print_statistics();
void signal_handle();

int main(int argc, char *argv[])
{
    stats = statistics_init();

    short capture_flag = 0, valid = 1;
    char *dev, *filter;
    int ch;
    char errbuf[PCAP_ERRBUF_SIZE];
    while ((ch = getopt(argc, argv, "r:f:i:h")) != -1)
    {
        switch (ch)
        {
        case 'r':
            if (access(optarg, F_OK) == 0 && argc == 3 && read_capture_file(optarg, errbuf) > 0)
            {
                print_statistics();
            }
            else if (access(optarg, F_OK) < 0 || argc != 3)
            {
                usage();
            }
            free(stats);
            return 1;
            break;
        case 'f':
            // Filter expression, ex. -f "port 8080"
            if (argc == 5 && strstr(optarg, "port ") != NULL)
            {
                filter = (char *)(strchr(optarg, ' ') + 1);
                port_filter = atoi(filter);
                if (port_filter < 1)
                {
                    printf("Invalid port, should be in range: [1, 65535]\n");
                }
            }
            else
            {
                valid = 0;
            }
            break;
        case 'i':
            capture_flag++;
            dev = optarg;
            break;
        case 'h':
        default:
            usage();
            break;
        }
    }

    if (capture_flag == 1 && valid == 1)
    {
        if (capture(dev) == 0)
        {
            print_statistics();
        }
    }
    else
    {
        usage();
    }

    free(stats);

    return 0;
}

void usage(void)
{
    printf(
        "usage:\n"
        "./pcap_ex -r <filename>\n"
        "./pcap_ex -i <dev> [-f] <expression> \n"
        "Options:\n"
        "-r <filename>, Prints packets information of a savefile\n"
        "-i <dev>, Start capture using the specified interface\n"
        "-f <expression>, Filter the capture with an expression\n"
        "-h, Help message\n\n");

    exit(1);
}

int read_capture_file(char *file, char *errbuf)
{
    pcap_t *savefile = pcap_open_offline(file, errbuf);
    stream = stderr;
    if (pcap_loop(savefile, 0, packet_handle, NULL) < 0)
    {
        printf("\npcap_loop failed");
        return 0;
    }

    pcap_close(savefile);
    return 1;
}

int capture(char *dev)
{
    pcap_t *handle;                // Session handle
    pcap_if_t *dev_list;           // Interface list
    char errbuf[PCAP_ERRBUF_SIZE]; // Error string

    // get interface list
    if (pcap_findalldevs(&dev_list, errbuf) != 0)
    {
        fprintf(stderr, "pcap_findalldevs failed: %s\n", errbuf);
        return -1;
    }

    // find input's device name
    while (dev_list != NULL)
    {
        if (strcmp(dev_list->name, dev) == 0)
        {
            break;
        }
        dev_list = dev_list->next;
    }

    // If doesnt exist, exit
    if (dev_list == NULL)
    {
        fprintf(stderr, "Interface %s doesn't exist\n", dev);
        return -1;
    }

    // Opens device for capturing
    handle = pcap_open_live(dev, MAX_SNAPLEN, 1, TIMEOUT, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    // open stream for writing at logfile
    stream = fopen(LOG_FILE, "w");

    printf("Capturing...");
    fflush(NULL);

    // start capturing packets, and call packet_handle callback funcion foreach one
    if (pcap_loop(handle, MAX_PACKETS, packet_handle, NULL) < 0)
    {
        fprintf(stream, "\npcap_loop failed");
        pcap_close(handle);
        fclose(stream);
        return -1;
    }

    // After finishing, close captured device and file stream
    pcap_close(handle);
    printf(" Completed!\n");
    fclose(stream);

    return 0;
}

// callback function used in pcap_loop
// Used for both reading a savefile and live capture, by either using
// the stderr stream or the fd of the logfile
void packet_handle(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // Initialize basic packet headers and variables
    const struct ether_header *ethernet_header;
    const struct tcphdr *tcp_hdr;
    const struct udphdr *udp_hdr;

    u_int source_port, dest_port;
    uint8_t protocol = IPPROTO_IP; // initialization used to bypass flow check in case packet nor TCP nor UDP
    int data_length = 0;

    // Start by reading the ethernet header of packet
    ethernet_header = (struct ether_header *)packet;

    // Check from ethernet header the ip protocol encapsulated in the packet's frame
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP)
    {
        // Use struct ip for ipv4 protocol
        const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header)); // point to ip header

        char source_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];

        // Create a presentable string for each ipv4 address (gathered from the ip_header)
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN); // get source ip
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);   // get destination ip

        // Check ip's encapsulated protocol
        if (ip_header->ip_p == IPPROTO_TCP)
        {
            // TCP protocol -> using tcphdr struct
            protocol = IPPROTO_TCP;

            // Moving pointer accordingly
            tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            // Convert the ports of the protocol from network bytes to u_int
            source_port = ntohs(tcp_hdr->source);
            dest_port = ntohs(tcp_hdr->dest);

            // Calculate payload's length
            data_length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

            // Statistics
            stats->tcp_cnt++;
            stats->tcp_b_cnt += pkthdr->len;

            // if port_filter == 0, no filter was used
            // if port_filter > 0, filter was used and should only display packets with src/dst port == port_filter
            if (port_filter == 0 ||
                (port_filter > 0 && (source_port == port_filter || dest_port == port_filter)))
            {
                fprintf(stream, "IP Version:       IPv4\n");
                fprintf(stream, "Source IP:        %s\n", source_ip);
                fprintf(stream, "Destination IP:   %s\n", dest_ip);
                fprintf(stream, "Source port:      %d\n", source_port);
                fprintf(stream, "Destination port: %d\n", dest_port);
                fprintf(stream, "Protocol:         TCP\n");
                fprintf(stream, "Header length:    %ld\n", sizeof(struct tcphdr));
                fprintf(stream, "Payload length:   %d\n", data_length);
                fprintf(stream, "Retransmission:   ");

                // Check RST flag of TCP header, if 1 then packet was retransmitted
                if (tcp_hdr->th_flags & TH_RST)
                {
                    fprintf(stream, "Yes");
                }
                else
                {
                    fprintf(stream, "No");
                }
                fprintf(stream, "\n\n");
            }
        }
        else if (ip_header->ip_p == IPPROTO_UDP)
        {
            // UDP protocol -> using udphdr struct
            protocol = IPPROTO_UDP;

            // Moving pointer accordingly
            udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

            // Convert the ports of the protocol from network bytes to u_int
            source_port = ntohs(udp_hdr->source);
            dest_port = ntohs(udp_hdr->dest);

            // Calculate payload's length
            data_length = ntohs(udp_hdr->len) - sizeof(struct udphdr);

            // Statistics
            stats->udp_cnt++;
            stats->udp_b_cnt += pkthdr->len;

            if (port_filter == 0 ||
                (port_filter > 0 && (source_port == port_filter || dest_port == port_filter)))
            {
                fprintf(stream, "IP Version:       IPv4\n");
                fprintf(stream, "Source IP:        %s\n", source_ip);
                fprintf(stream, "Destination IP:   %s\n", dest_ip);
                fprintf(stream, "Source port:      %d\n", source_port);
                fprintf(stream, "Destination port: %d\n", dest_port);
                fprintf(stream, "Protocol:         UDP\n");
                fprintf(stream, "Header length:    %ld\n", sizeof(struct udphdr));
                fprintf(stream, "Payload length:   %d\n\n", data_length);
            }
        }

        // Check for duplicate flow for ipv4
        if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
        {
            int exists = 0;
            int max = stats->network_flows_cnt;

            // foreach entry inside the flows array, check for same 5-tuple
            for (int i = 0; i < max; i++)
            {
                if (memcmp(&flows[i].src_ip.ipv4, &ip_header->ip_src, sizeof(struct in_addr)) == 0 &&
                    memcmp(&flows[i].dst_ip.ipv4, &ip_header->ip_dst, sizeof(struct in_addr)) == 0 &&
                    flows[i].src_port == source_port &&
                    flows[i].dst_port == dest_port &&
                    flows[i].protocol == protocol)
                {
                    exists = 1;
                    break;
                }
            }

            // Add new flow
            if (exists == 0)
            {
                flows[max].src_ip.ipv4 = ip_header->ip_src;
                flows[max].dst_ip.ipv4 = ip_header->ip_dst;
                flows[max].src_port = source_port;
                flows[max].dst_port = dest_port;
                flows[max].protocol = protocol;

                stats->network_flows_cnt++;
                if (protocol == IPPROTO_TCP)
                {
                    stats->tcp_flows_cnt++;
                }
                else
                {
                    stats->udp_flows_cnt++;
                }
            }
        }
    }
    else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6)
    {
        // Use struct ip6_hdr for ipv6 protocol
        const struct ip6_hdr *ip_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header)); // point to ip header

        sizeof(struct in6_addr);
        char source_ip[INET6_ADDRSTRLEN];
        char dest_ip[INET6_ADDRSTRLEN];

        // Create a presentable string for each ipv6 address (gathered from the ip_header)
        inet_ntop(AF_INET6, &(ip_header->ip6_src), source_ip, INET6_ADDRSTRLEN); // get source ip
        inet_ntop(AF_INET6, &(ip_header->ip6_dst), dest_ip, INET6_ADDRSTRLEN);   // get destination ip

        // Check protocol after ipv6 protocol
        if (ip_header->ip6_nxt == IPPROTO_TCP)
        {
            protocol = IPPROTO_TCP;
            tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            source_port = ntohs(tcp_hdr->source);
            dest_port = ntohs(tcp_hdr->dest);
            data_length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            stats->tcp_cnt++;
            stats->tcp_b_cnt += pkthdr->len;

            if (port_filter == 0 ||
                (port_filter > 0 && (source_port == port_filter || dest_port == port_filter)))
            {
                fprintf(stream, "IP Version:       IPv6\n");
                fprintf(stream, "Source IP:        %s\n", source_ip);
                fprintf(stream, "Destination IP:   %s\n", dest_ip);
                fprintf(stream, "Source port:      %d\n", source_port);
                fprintf(stream, "Destination port: %d\n", dest_port);
                fprintf(stream, "Protocol:         TCP\n");
                fprintf(stream, "Header length:    %ld\n", sizeof(struct tcphdr));
                fprintf(stream, "Payload length:   %d\n", data_length);
                fprintf(stream, "Retransmission:   ");
                if (tcp_hdr->th_flags & TH_RST)
                {
                    fprintf(stream, "Yes");
                }
                else
                {
                    fprintf(stream, "No");
                }
                fprintf(stream, "\n\n");
            }
        }
        else if (ip_header->ip6_nxt == IPPROTO_UDP)
        {
            protocol = IPPROTO_UDP;
            udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            source_port = ntohs(udp_hdr->source);
            dest_port = ntohs(udp_hdr->dest);
            data_length = ntohs(udp_hdr->len) - sizeof(struct udphdr);

            stats->udp_cnt++;
            stats->udp_b_cnt += pkthdr->len;

            if (port_filter == 0 ||
                (port_filter > 0 && (source_port == port_filter || dest_port == port_filter)))
            {
                fprintf(stream, "IP Version:       IPv6\n");
                fprintf(stream, "Source IP:        %s\n", source_ip);
                fprintf(stream, "Destination IP:   %s\n", dest_ip);
                fprintf(stream, "Source port:      %d\n", source_port);
                fprintf(stream, "Destination port: %d\n", dest_port);
                fprintf(stream, "Protocol:         UDP\n");
                fprintf(stream, "Header length:    %ld\n", sizeof(struct udphdr));
                fprintf(stream, "Payload length:   %d\n\n", data_length);
            }
        }

        // Check for duplicate flow for ipv6
        if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
        {
            int exists = 0;
            int max = stats->network_flows_cnt;
            for (int i = 0; i < max; i++)
            {
                if (memcmp(&flows[i].dst_ip.ipv6, &ip_header->ip6_dst, sizeof(struct in6_addr)) == 0 &&
                    memcmp(&flows[i].src_ip.ipv6, &ip_header->ip6_src, sizeof(struct in6_addr)) == 0 &&
                    flows[i].src_port == source_port &&
                    flows[i].dst_port == dest_port &&
                    flows[i].protocol == protocol)
                {
                    exists = 1;
                    break;
                }
            }

            // Add new flow
            if (exists == 0)
            {
                flows[max].dst_ip.ipv6 = ip_header->ip6_dst;
                flows[max].src_ip.ipv6 = ip_header->ip6_src;
                flows[max].src_port = source_port;
                flows[max].dst_port = dest_port;
                flows[max].protocol = protocol;

                stats->network_flows_cnt++;
                if (protocol == IPPROTO_TCP)
                {
                    stats->tcp_flows_cnt++;
                }
                else
                {
                    stats->udp_flows_cnt++;
                }
            }
        }
    }

    stats->pckt_cnt++;
}

// Init statistics, used in global scope
statistics *statistics_init()
{
    struct statistics *stats = (struct statistics *)malloc(sizeof(struct statistics));

    stats->network_flows_cnt = 0;
    stats->tcp_flows_cnt = 0;
    stats->udp_flows_cnt = 0;
    stats->pckt_cnt = 0;
    stats->tcp_cnt = 0;
    stats->udp_cnt = 0;
    stats->tcp_b_cnt = 0;
    stats->udp_b_cnt = 0;

    return stats;
}

void print_statistics()
{
    printf("================================================\n");
    printf("[                   Statistics                 ]\n");
    printf("================================================\n\n");
    printf("• Total number of network flows captured: %d\n", stats->network_flows_cnt);
    printf("• Number of TCP network flows captured:   %d\n", stats->tcp_flows_cnt);
    printf("• Number of UDP network flows captured:   %d\n", stats->udp_flows_cnt);
    printf("• Total number of packets received:       %d\n", stats->pckt_cnt);
    printf("• Number of TCP packets received:         %d\n", stats->tcp_cnt);
    printf("• Number of UDP packets received:         %d\n", stats->udp_cnt);
    printf("• Total bytes of TCP packets received:    %d\n", stats->tcp_b_cnt);
    printf("• Total bytes of UDP packets received:    %d\n\n", stats->udp_b_cnt);
};