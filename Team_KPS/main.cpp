#include <string>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using namespace std;

void show_interface();
void traffic(const char *interface);
void pcap_f(const char *file);
void analysis(pcap_t * pcap);
void usage();
void print_mac(u_int8_t *smac, u_int8_t *dmac, u_int16_t type);
void print_binary(u_char *payload, int length);

int main(int argc, char *argv[])
{
    switch (argc) {
    case 3:
        if (strcmp(argv[1], "-t") == 0) {
            const char *interface = argv[2];
            traffic(interface);
        } else if (strcmp(argv[1], "-f") == 0) {
            const char *file = argv[2];
            pcap_f(file);
        } else {
            usage();
        }
        break;
    default:
        usage();
        return -1;
    }
}

void show_interface() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Show Interface
    pcap_if_t *alldevs;
    pcap_if_t *d;

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        fprintf(stderr, "pcap_findalldevs - %s\n", errbuf);
        exit(-1);
    }

    printf("Interface:\n");
    for (d=alldevs; d; d=d->next) {
        printf("\t%s\n", (d->description)?(d->description):(d->name));
    }
    printf("\n");
}

void traffic(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *traffic = pcap_open_live(interface, 65536, 1, 1000, errbuf);
    if (traffic == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", interface, errbuf);
        exit(-1);
    }

    analysis(traffic);
}

void pcap_f(const char *file) {
    // Create an char array to hold the error.
    char errbuf[PCAP_ERRBUF_SIZE];
 
    // Step 4 - Open the file and store result in pointer to pcap_t
    pcap_t * pcap = pcap_open_offline(file, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_offline(%s) return nullptr - %s\n", file, errbuf);
        exit(-1);
    }

    analysis(pcap);
}

void analysis(pcap_t * pcap) {
    // Step 5 - Create a header and a data object
    struct pcap_pkthdr *header;
    struct ether_header *eth_header;
    struct ip *ip_header;
    int ip_len;

    struct tcphdr *tcp_header;
    int tcp_len;
    u_char *tcp_payload;

    u_char *payload;
    int payload_size;
    int payload_test;
    
    const u_char *data;
    // Step 6 - Loop through packets and print them to screen
    u_int packetCount = 0;
    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        sleep(0);
        if (returnValue == 0) continue;
        if (returnValue == -1 || returnValue == -2) {
            printf("pcap_next_ex return %d(%s)\n", returnValue, pcap_geterr(pcap));
            break;
        }

        // Show the Ethernet header info
        eth_header = (struct ether_header *)(data);
        u_int8_t *dmac = eth_header->ether_dhost;
        u_int8_t *smac = eth_header->ether_shost;
        u_int16_t type = ntohs(eth_header->ether_type);

        // Show the IP header info
        ip_header = (struct ip *)(data + sizeof(struct ether_header));
        ip_len = ip_header->ip_hl << 2;

        // Show the packet number
        printf("Packet # %i\n", ++packetCount);
 
        // Show the size in bytes of the packet
        printf("Packet size: %d bytes\n", header->len);
 
        // Show a warning if the length captured is different
        if (header->len != header->caplen)
            printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);
 
        // Show Epoch Time
        printf("Epoch Time: %d:%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);

        // Show MAC Info
        print_mac(smac, dmac, type);
        if (type == ETHERTYPE_IP) {
            /*
            To Do..
            1. IP Upper Layer Classifer (ICMP, IGMP, TCP, UDP)
            REF) Protocol Identifier 필드(8bit); 상위 계층 프로토콜
            1 - ICMP, 2 - IGMP, 6 - TCP, 17 - UDP
            enum
              {
                IPPROTO_IP = 0,         Dummy protocol for TCP.  
            #define IPPROTO_IP              IPPROTO_IP
                IPPROTO_ICMP = 1,       Internet Control Message Protocol.  
            #define IPPROTO_ICMP            IPPROTO_ICMP
                IPPROTO_IGMP = 2,       Internet Group Management Protocol. 
            #define IPPROTO_IGMP            IPPROTO_IGMP
                IPPROTO_IPIP = 4,       IPIP tunnels (older KA9Q tunnels use 94).  
            #define IPPROTO_IPIP            IPPROTO_IPIP
                IPPROTO_TCP = 6,        Transmission Control Protocol.  
            #define IPPROTO_TCP             IPPROTO_TCP
                IPPROTO_EGP = 8,        Exterior Gateway Protocol.  
            #define IPPROTO_EGP             IPPROTO_EGP
                IPPROTO_PUP = 12,       PUP protocol.  
            #define IPPROTO_PUP             IPPROTO_PUP
                IPPROTO_UDP = 17,       User Datagram Protocol.  
            #define IPPROTO_UDP             IPPROTO_UDP
                IPPROTO_IDP = 22,       XNS IDP protocol.  
            #define IPPROTO_IDP             IPPROTO_IDP
                IPPROTO_TP = 29,        SO Transport Protocol Class 4.  
            #define IPPROTO_TP              IPPROTO_TP
                IPPROTO_DCCP = 33,      Datagram Congestion Control Protocol.  
            #define IPPROTO_DCCP            IPPROTO_DCCP
                IPPROTO_IPV6 = 41,      IPv6 header.  
            #define IPPROTO_IPV6            IPPROTO_IPV6
                IPPROTO_RSVP = 46,      Reservation Protocol.  
            #define IPPROTO_RSVP            IPPROTO_RSVP
                IPPROTO_GRE = 47,       General Routing Encapsulation.  
            #define IPPROTO_GRE             IPPROTO_GRE
                IPPROTO_ESP = 50,       encapsulating security payload.  
            #define IPPROTO_ESP             IPPROTO_ESP
                IPPROTO_AH = 51,        authentication header.  
            #define IPPROTO_AH              IPPROTO_AH
                IPPROTO_MTP = 92,       Multicast Transport Protocol.  
            #define IPPROTO_MTP             IPPROTO_MTP
                IPPROTO_BEETPH = 94,    IP option pseudo header for BEET. 
            #define IPPROTO_BEETPH          IPPROTO_BEETPH
                IPPROTO_ENCAP = 98,     Encapsulation Header.  
            #define IPPROTO_ENCAP           IPPROTO_ENCAP
                IPPROTO_PIM = 103,      Protocol Independent Multicast.  
            #define IPPROTO_PIM             IPPROTO_PIM
                IPPROTO_COMP = 108,     Compression Header Protocol.  
            #define IPPROTO_COMP            IPPROTO_COMP
                IPPROTO_SCTP = 132,     Stream Control Transmission Protocol.  
            #define IPPROTO_SCTP            IPPROTO_SCTP
                IPPROTO_UDPLITE = 136,  UDP-Lite protocol.  
            #define IPPROTO_UDPLITE         IPPROTO_UDPLITE
                IPPROTO_MPLS = 137,     MPLS in IP.  
            #define IPPROTO_MPLS            IPPROTO_MPLS
                IPPROTO_RAW = 255,      Raw IP packets.  
            #define IPPROTO_RAW             IPPROTO_RAW
                IPPROTO_MAX
              };
            */
            switch (ip_header->ip_p) {
                case IPPROTO_TCP:
                    // Show the TCP header info
                    tcp_header = (struct tcphdr *)(data + sizeof(struct ether_header) + ip_len);
                    tcp_len = tcp_header->th_off << 2;
                    tcp_payload = (u_char *)(data + sizeof(struct ether_header) + ip_len);

                    // SHOW IP TCP Info
                    printf("Src: %s:%d\n", inet_ntoa(ip_header->ip_src), ntohs(tcp_header->th_sport));
                    printf("Dest: %s:%d\n", inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->th_dport));

                    // Show the Payload info
                    payload = (u_char *)(data + sizeof(struct ether_header) + ip_len + tcp_len);
                    payload_size = ntohs(ip_header->ip_len) - (tcp_len + ip_len);

                    // TCP Function();
                    // loop through the packet and print it as hexidecimal representations of octets
                    // We also have a function that does this similarly below: PrintData()
                    printf("<TCP Payload>");
                    print_binary(tcp_payload, tcp_len);
                    
                    printf("\n<Payload>");
                    if (payload_size == 0) printf("\nPayload Data Not Found...");
                    else {
                        print_binary(payload, payload_size);
                        if (ntohs(tcp_header->th_sport)==587 || ntohs(tcp_header->th_sport)==3326)
                            smtp_analysis(payload, payload_size);
                        // else if () http_analysis
                        // else if () ftp_analysis
                    }
                    
                    break;
                case IPPROTO_ICMP:
                    // ICMP Function();
                    break;
                case IPPROTO_IGMP:
                    // IGMP Function();
                    break;
                default:
                    // Unknown Fucntion();
                    break;
            }

            // Packet Memory initialization
            memset(ip_header, '\0', ntohs(ip_header->ip_len));
        }  
        
        // Add two lines between packets
        printf("\n\n");
    }
}

void usage() {
    show_interface();
    printf("syntax: sudo pcap-test -t <interface>\n");
    printf("sample: pcap-test -t eth0\n");
    printf("syntax: pcap-test -f <pcap file>\n");
    printf("sample: pcap-test -f smtp.pcap\n");
}

void print_mac(u_int8_t *smac, u_int8_t *dmac, u_int16_t type) {
    printf("Src MAC: ");
    for (int i=0; i<ETHER_ADDR_LEN; i++) {
        if (i == (ETHER_ADDR_LEN-1)) printf("%02x\n", smac[i]);
        else printf("%02x:", smac[i]);
    }
    printf("Dst MAC: ");
    for (int i=0; i<ETHER_ADDR_LEN; i++) {
        if (i == (ETHER_ADDR_LEN-1)) printf("%02x\n", dmac[i]);
        else printf("%02x:", dmac[i]);
    }

    const char *name = NULL;
    switch (type) {
        case ETHERTYPE_IP:
            name = "IP";
            break;
        case ETHERTYPE_ARP:
            name = "ARP";
            break;
        case ETHERTYPE_PUP:
            name = "PUP";
            break;
        case ETHERTYPE_SPRITE:
            name = "SPRITE";
            break;
        case ETHERTYPE_REVARP:
            name = "REVARP";
            break;
        case ETHERTYPE_AT:
            name = "AT";
            break;
        case ETHERTYPE_AARP:
            name = "AARP";
            break;
        case ETHERTYPE_VLAN:
            name = "VLAN";
            break;
        case ETHERTYPE_IPX:
            name = "IPX";
            break;
        case ETHERTYPE_IPV6:
            name = "IPV6";
            break;
        case ETHERTYPE_LOOPBACK:
            name = "LOOPBACK";
            break;
        default:
            name = "Unknwon";
            break;
    }
    printf("Type: %s\n", name);
}

void print_binary(u_char *payload, int length) {
    for (u_int i=0; i<length; i++)
    {
        // Start printing on the next after every 16 octets
        if ( (i % 16) == 0) {
            printf("\n0x%04x ", i);
        }
        // Print each octet as hex (x), make sure there is always two characters (.2).
        printf("%02x ", payload[i]);
    }
}