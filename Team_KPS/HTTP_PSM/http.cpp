#include "http.h"

/* Seung Min Code */

static std::map<u_int16_t, IPv4_INFO> receiver;

void http_analysis (struct tcphdr *tcp_header, struct ip *ip_header, u_char *payload, int payload_size) {
    u_int8_t REQUEST = 1;
    u_int8_t RESPONSE = 0;

    if (ntohs(tcp_header->th_dport) == 80) {
        IPv4_INFO packet_info;
        
        // ipv4 만들기
        packet_info.sport = ntohs(tcp_header->th_sport);
        packet_info.dport = ntohs(tcp_header->th_dport);
        packet_info.sip   = ntohl(ip_header->ip_src.s_addr);
        packet_info.dip   = ntohl(ip_header->ip_dst.s_addr);

        // receiver에 넣기
        receiver.insert(std::make_pair(packet_info.sport, packet_info));

        handle_http(payload, payload_size, receiver, ntohs(tcp_header->th_sport), REQUEST);
    }
    else if (ntohs(tcp_header->th_sport) == 80) {
        // 함수로 넘겨서 처리
        handle_http(payload, payload_size, receiver, ntohs(tcp_header->th_dport), RESPONSE);
    }
}

void handle_http (u_char *payload, int payload_size, std::map<u_int16_t, IPv4_INFO> &receiver, u_int16_t my_port, u_int8_t request_flag) {
    printf("call handle_http\n");
    
    // request packet
    if (request_flag == 1) {
        // make path and file
        // receiver[my_port].

        // header에서 3줄을 읽어와 헤더 파일에 쓰기
        // [GET/POST] [File Name] [HTTP Version]    // line 1
        // HOST: [HOSTNAME]
        // USER-AGENT: [USERAGENT]

        // line 1에 존재하는 [File Name]을 구조체에 적기
        // File Name에 /를 $로 바꿈
    }
    // response packet
    else if (request_flag == 0) {
        // filename 읽어와 해당 file에 data append
        
        // 파일이 존재하지 않았던, 첫 작성일 경우 헤더를 request 헤더 작성한 곳에 작성
        // [Response Code]                        // line 1
        // Content-Encoding: [Encoding]
        // Content-Type: [Type]
        // Date: [Date]
        // Server: [Server]

        // 이미 존재하던 파일의 경우 body를 append로 작성
    }
}




/* Seung Min Code End */
