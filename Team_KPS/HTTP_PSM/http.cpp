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

/**
 * Function to check whether a directory exists or not.
 * It returns 1 if given path is directory and  exists 
 * otherwise returns 0.
 */
int isDirectoryExists(const char *path) {
    struct stat stats;

    stat(path, &stats);

    // Check for file existence
    if (S_ISDIR(stats.st_mode))
        return 1;

    return 0;
}

std::string replaceAll(const std::string &str, const std::string &pattern, const std::string &replace) {
	std::string result = str;
	std::string::size_type pos = 0;
	std::string::size_type offset = 0;

	while((pos = result.find(pattern, offset)) != std::string::npos)
	{
		result.replace(result.begin() + pos, result.begin() + pos + pattern.size(), replace);
		offset = pos + replace.size();
	}

	return result;
}

void handle_http (u_char *payload, int payload_size, std::map<u_int16_t, IPv4_INFO> &receiver, u_int16_t my_port, u_int8_t request_flag) {
    // request packet
    if (request_flag == 1) {

        // make path and file
        char base_dir[256] = "./OUTPUT/";
        if (isDirectoryExists(base_dir) == 0) {
            int nResult = mkdir(base_dir, 0666);

            if(nResult == 0) {
                printf( "[ip] 폴더 생성 성공\n" );
            }
            else if (nResult == -1) {
                perror( "[ip] 폴더 생성 실패 - 폴더가 이미 있거나 부정확함\n" );
                printf( "errorno : %d\n", errno );
            }
        }

        strcpy(base_dir, "./OUTPUT/HTTP/");
        if (isDirectoryExists(base_dir) == 0) {
            int nResult = mkdir(base_dir, 0666);

            if(nResult == 0) {
                printf( "[ip] 폴더 생성 성공\n" );
            }
            else if (nResult == -1) {
                perror( "[ip] 폴더 생성 실패 - 폴더가 이미 있거나 부정확함\n" );
                printf( "errorno : %d\n", errno );
            }
        }

        strcat(base_dir, inet_ntoa(* (struct in_addr *) &receiver[my_port].dip));
        if (isDirectoryExists(base_dir) == 0) {
            int nResult = mkdir(base_dir, 0666);

            if(nResult == 0) {
                printf( "[ip] 폴더 생성 성공\n" );
            }
            else if (nResult == -1) {
                perror( "[ip] 폴더 생성 실패 - 폴더가 이미 있거나 부정확함\n" );
                printf( "errorno : %d\n", errno );
            }
        }

        char port[7] = {0};
        snprintf(port, 7, "%u", my_port);
        strcat(base_dir, "/");
        strcat(base_dir, port);
        if (isDirectoryExists(base_dir) == 0) {
            int nResult = mkdir(base_dir, 0666);

            if(nResult == 0) {
                printf( "[port] 폴더 생성 성공 - port\n" );
            }
            else if (nResult == -1) {
                perror( "[port] 폴더 생성 실패 - 폴더가 이미 있거나 부정확함\n" );
                printf( "errorno : %d\n", errno );
            }
        }

        // header에서 3줄을 읽어와 헤더 파일에 쓰기
        // [GET/POST] [File Name] [HTTP Version]    // line 1
        // HOST: [HOSTNAME]
        // USER-AGENT: [USERAGENT]
        std::string request_header((char *)payload);
        int now = 0;
        u_int8_t firstline = 1;

        while (now != request_header.find("\r\n", now) + 2) {
            int next = request_header.find("\r\n", now);
            std::string line = request_header.substr(now, next);
            now = next+2;
            std::cout << "line : " + line << std::endl;

            if (firstline == 1) {
                // line 1에 존재하는 [File Name]을 구조체에 적기
                int space1 = line.find(" ");
                int space2 = line.find(" ", space1+1); // 마지막 스페이스로 바꿔야함 ///////////////////////////////////////////////////////
                std::string str_file_name = line.substr(space1+1, space2);
                // File Name에 /를 $로 바꿈
                std::cout << "str_file_name : " + str_file_name << std::endl;
                replaceAll(str_file_name, "/", "#");
                char *file_name = &str_file_name[0];
                strcpy(receiver[my_port].file_name, file_name);
                std::cout << "str_file_name_replace : " + str_file_name << std::endl;
            }

            std::fstream head_file;
            strcat(base_dir, "/");
            strcat(base_dir, receiver[my_port].file_name);
            head_file.open(base_dir, std::ios::app);
            head_file << line << std::endl;
            head_file.close();
        }
    }
    // response packet
    else if (request_flag == 0) {
        printf("request file 이에요 :D\n");
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
