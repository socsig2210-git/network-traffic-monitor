#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>

#include <netinet/in.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define MAX_FLOWS 1000

typedef struct flow
{
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
struct statistics *stats;

void usage();
int open_capture_file(char *, char *);
void packet_handle(u_char *, const struct pcap_pkthdr *, const u_char *);
struct statistics *statistics_init();
void print_statistics();
void signal_handle();

int main(int argc, char *argv[])
{
    short sig = 0;
    stats = statistics_init();

    int ch;
    char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
    while ((ch = getopt(argc, argv, "r:f:i:h")) != -1)
    {
        switch (ch)
        {
        case 'r':
            if (access(optarg, F_OK) == 0 && open_capture_file(optarg, errbuf) > 0)
            {
                print_statistics();
            }
            else if (access(optarg, F_OK) < 0)
            {
                usage();
            }
            // prints output of .pcap file in terminal
            break;
        case 'f':
            // Filter expression, ex. -f "port 8080"
            break;
        case 'i':
            // Capture packets of interface in log.txt file
            // save_packets(optarg), optarg: interface name
            signal(SIGINT, signal_handle);
            printf("-----------------------------------------\n");
            printf("Press Ctrl+C to terminate the program\n");
            while (sig == 0)
            {
                // save_packets(optarg), optarg: interface name
            }
            break;
        case 'h':
        default:
            usage();
            break;
        }
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

int open_capture_file(char *file, char *errbuf)
{
    pcap_t *savefile = pcap_open_offline(file, errbuf);

    if (pcap_loop(savefile, 0, (*packet_handle), NULL) < 0)
    {
        printf("\npcap_loop failed");
        return 0;
    }

    pcap_close(savefile);
    return 1;
}

void packet_handle(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    const struct ether_header *ethernet_header;
    const struct tcphdr *tcp_hdr;
    const struct udphdr *udp_hdr;

    u_int source_port, dest_port;
    int data_length = 0;

    ethernet_header = (struct ether_header *)packet;
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP)
    {
        const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header)); // point to ip header

        char source_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN); // get source ip
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);   // get destination ip

        if (ip_header->ip_p == IPPROTO_TCP)
        {

            tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            source_port = ntohs(tcp_hdr->source);
            dest_port = ntohs(tcp_hdr->dest);
            data_length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            stats->tcp_cnt++;
            stats->tcp_b_cnt += pkthdr->len;

            printf("Total length:     %d\n", pkthdr->len);
            printf("IP Version:       IPv4\n");
            printf("Source IP:        %s\n", source_ip);
            printf("Destination IP:   %s\n", dest_ip);
            printf("Source port:      %d\n", source_port);
            printf("Destination port: %d\n", dest_port);
            printf("Protocol:         TCP\n");
            printf("Header length:    %ld\n", sizeof(struct tcphdr));
            printf("Payload length:   %d\n", data_length);
            printf("Retransmission:   ");
            if (tcp_hdr->th_flags & TH_RST)
            {
                printf("Yes");
            }
            else
            {
                printf("No");
            }

            printf("\n\n\n");
        }
        else if (ip_header->ip_p == IPPROTO_UDP)
        {
            udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            source_port = ntohs(udp_hdr->source);
            dest_port = ntohs(udp_hdr->dest);
            data_length = ntohs(udp_hdr->len) - sizeof(struct udphdr);
            // data_length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            stats->udp_cnt++;
            stats->udp_b_cnt += pkthdr->len;

            printf("Total length:     %d\n", pkthdr->len);
            printf("IP Version:       IPv4\n");
            printf("Source IP:        %s\n", source_ip);
            printf("Destination IP:   %s\n", dest_ip);
            printf("Source port:      %d\n", source_port);
            printf("Destination port: %d\n", dest_port);
            printf("Protocol:         UDP\n");
            printf("Header length:    %ld\n", sizeof(struct udphdr));
            printf("Payload length:   %d\n\n\n", data_length);
        }
    }
    else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IPV6)
    {
        const struct ip6_hdr *ip_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header)); // point to ip header

        sizeof(struct in6_addr);
        char source_ip[INET6_ADDRSTRLEN];
        char dest_ip[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &(ip_header->ip6_src.__in6_u), source_ip, INET6_ADDRSTRLEN); // get source ip
        inet_ntop(AF_INET6, &(ip_header->ip6_dst), dest_ip, INET6_ADDRSTRLEN);   // get destination ip

        if (ip_header->ip6_nxt == IPPROTO_TCP)
        {
            tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            source_port = ntohs(tcp_hdr->source);
            dest_port = ntohs(tcp_hdr->dest);
            data_length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            stats->tcp_cnt++;
            stats->tcp_b_cnt += pkthdr->len;

            printf("Total length:     %d\n", pkthdr->len);
            printf("IP Version:       IPv6\n");
            printf("Source IP:        %s\n", source_ip);
            printf("Destination IP:   %s\n", dest_ip);
            printf("Source port:      %d\n", source_port);
            printf("Destination port: %d\n", dest_port);
            printf("Protocol:         TCP\n");
            printf("Header length:    %ld\n", sizeof(struct tcphdr));
            printf("Payload length:   %d\n\n\n", data_length);
            printf("Retransmission:   ");
            if (tcp_hdr->th_flags & TH_RST)
            {
                printf("Yes");
            }
            else
            {
                printf("No");
            }

            printf("\n\n\n");
        }
        else if (ip_header->ip6_nxt == IPPROTO_UDP)
        {
            udp_hdr = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            source_port = ntohs(udp_hdr->source);
            dest_port = ntohs(udp_hdr->dest);
            data_length = ntohs(udp_hdr->len) - sizeof(struct udphdr);
            // data_length = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
            stats->udp_cnt++;
            stats->udp_b_cnt += pkthdr->len;

            printf("Total length:     %d\n", pkthdr->len);
            printf("IP Version:       IPv6\n");
            printf("Source IP:        %s\n", source_ip);
            printf("Destination IP:   %s\n", dest_ip);
            printf("Source port:      %d\n", source_port);
            printf("Destination port: %d\n", dest_port);
            printf("Protocol:         UDP\n");
            printf("Header length:    %ld\n", sizeof(struct udphdr));
            printf("Payload length:   %d\n\n\n", data_length);
        }
    }

    stats->pckt_cnt++;
}

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

void print_packet()
{
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

// void signal_handle(int sig)
// {
//     printf("\n\n");
//     print_statistics();
//     exit(1);   
// }