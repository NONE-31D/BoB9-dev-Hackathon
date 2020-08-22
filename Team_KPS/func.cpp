#include "stdafx.h"
#include "SMTP_KBS/smtp.h"
#include "HTTP_PSM/http.h"
#include "FTP_SYL/FTP.h"

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
            switch (ip_header->ip_p) {
                case IPPROTO_TCP:
                    // Show the TCP header info
                    tcp_header = (struct tcphdr *)(data + sizeof(struct ether_header) + ip_len);
                    tcp_len = tcp_header->th_off << 2;

                    // SHOW IP TCP Info
                    printf("Src: %s:%d\n", inet_ntoa(ip_header->ip_src), ntohs(tcp_header->th_sport));
                    printf("Dest: %s:%d\n", inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->th_dport));

                    // Show the Payload info
                    payload = (u_char *)(data + sizeof(struct ether_header) + ip_len + tcp_len);
                    payload_size = ntohs(ip_header->ip_len) - (tcp_len + ip_len);

                    if (payload_size == 0) printf("Payload Data Not Found...\n");
                    else {
                        if (ntohs(tcp_header->th_sport)==587 || ntohs(tcp_header->th_sport)==3326)
                           smtp_analysis(ntohs(tcp_header->th_sport), payload, payload_size);
                        else if (ntohs(tcp_header->th_sport) == 80 || ntohs(tcp_header->th_dport) == 80);
                            // http_analysis(tcp_header, ip_header, payload, payload_size);
                        else if (ntohs(tcp_header->th_sport) == 21 || ntohs(tcp_header->th_dport) == 21)
                            ftp_analysis(payload, payload_size);
                        else if ((ntohs(tcp_header->th_sport) == 20 || ntohs(tcp_header->th_dport) == 20)&& is_file_mining == 2)
                            ftp_fileMining(payload, payload_size);
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
        }
        // Packet Memory initialization
        memset(ip_header, '\0', ntohs(ip_header->ip_len));
        memset(tcp_header, '\0', tcp_len);
        memset(payload, '\0', payload_size);

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