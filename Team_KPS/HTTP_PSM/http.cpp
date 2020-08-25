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
        packet_info.sip   = ip_header->ip_src.s_addr;
        packet_info.dip   = ip_header->ip_dst.s_addr;
        memset(packet_info.file_name, 0, sizeof(packet_info.file_name));

        // packet_info.sip   = ntohl(ip_header->ip_src.s_addr);
        // packet_info.dip   = ntohl(ip_header->ip_dst.s_addr);

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

int parsing (u_char *payload, int payload_size) {
    int i = 0;

    for (; i < payload_size; i++) {
        if (payload[i] == '\r' && payload[i+1] == '\n') return i;
    }
    
    return i;
}

void change_directory_name (char *file_name) {
    int name_length = strlen((char *) file_name);
    for (int i = 0; i < name_length; i++) {
        if (file_name[i] == '/') file_name[i] = '_';
    }
    file_name[name_length] = '\0';
}

void parsing_request (u_char *payload, int payload_size, std::map<u_int16_t, IPv4_INFO> &receiver, u_int16_t my_port) {
    int start = 0;
    int end = parsing(payload, payload_size);

    char *first_line = (char *) malloc (sizeof(char) * end + 1);
    memcpy(first_line, payload, end);

    // first line parsing -> get file name
    char *sub_str = strtok((char *) payload, " ");
    printf("\nrequest mode : %s\n", sub_str);

    memset(receiver[my_port].file_name, 0, 256);
    sub_str = strtok(NULL, " ");
    memcpy(receiver[my_port].file_name, sub_str, strlen(sub_str));
    change_directory_name(receiver[my_port].file_name);
    printf("file name : %s -> %s(%d)\n", sub_str, receiver[my_port].file_name, strlen(receiver[my_port].file_name));

    // file open
    char file_path[256] = {0, };
    strcat(file_path, receiver[my_port].file_name);

    FILE *fp = fopen(file_path, "a");
    if (fp == NULL) {
        printf("NULL POINTER RETURNED...\n");
        printf("strerror(errno) : %s\n", strerror(errno));
        perror("perror : ");
        return;
    }

    // all of the lines save to file
    fprintf(fp, "%s\n", first_line);
    printf("file write : %s\n", first_line);
    while (start < end) {
        start = end+2;
        end = start + parsing(payload+start, payload_size-start);
        if (start > end) break;

        char *temp = (char *) malloc(sizeof(char) * (end-start));
        strncpy(temp, (char *) payload+start, end-start);
        fprintf(fp, "%s\n", temp);
        printf("file write : %s\n", temp);
        free(temp);
    }
    
    fclose(fp);
}

void parsing_response (u_char *payload, int payload_size, std::map<u_int16_t, IPv4_INFO> &receiver, u_int16_t my_port) {
    // 파일이 존재하지 않았던, 첫 작성일 경우 헤더를 request 헤더 작성한 곳에 작성

    printf("[RESPONSE] file name... %s\n", receiver[my_port].file_name);

    // File not exists
    int pointer = 0;
    if (access(receiver[my_port].file_name, F_OK) == -1) {
        if (chdir("./HEADER") == -1) {
            fprintf(stderr, "Cannot change working directory to HEADER dir..\n");
            return;
        }

        FILE *fp = fopen(receiver[my_port].file_name, "a");
        int start = 0;
        int end = parsing(payload, payload_size);
        char *first_line = (char *) malloc (sizeof(char) * end + 1);
        memcpy(first_line, payload, end);

        fprintf(fp, "%s\n", first_line);
        printf("file write : %s\n", first_line);
        while (start < end) {
            start = end+2;
            end = start + parsing(payload+start, payload_size-start);
            if (start >= end) break;

            char *temp = (char *) malloc(sizeof(char) * (end-start));
            strncpy(temp, (char *) payload+start, end-start);
            fprintf(fp, "%s\n", temp);
            printf("file write : %s\n", temp);
            free(temp);
        }

        fclose(fp);
        pointer = end+2;

        if (chdir("../") == -1) {
            fprintf(stderr, "Cannot change working directory to files dir..\n");
            return;
        }

        fp = fopen(receiver[my_port].file_name, "w");
        fclose(fp);
    }
        
    printf("\n SAVING HTTP HEADER COMPLETE ! ======================================\n");

    // 이미 존재하던 파일의 경우 body를 append로 작성
    FILE *fp = fopen(receiver[my_port].file_name, "ab");
    int ret = fwrite(payload+pointer, sizeof(char), payload_size - pointer, fp);
    printf("%d write -> fwrite return %d\n", payload_size-pointer, ret);
    fclose(fp);
}

void handle_http (u_char *payload, int payload_size, std::map<u_int16_t, IPv4_INFO> &receiver, u_int16_t my_port, u_int8_t request_flag) {
    // request packet
    if (request_flag == 1) {
        
        char curdir[256] = {0, };
        if (getcwd(curdir, 256) == NULL) {
            printf("%s\n", curdir);
            fprintf(stderr, "Cannot save current directory\n");
            return;
        }

        // make path and file
        char base_dir[256] = "./OUTPUT";
        if (isDirectoryExists(base_dir) == 0) {
            int nResult = mkdir(base_dir, 0777);

            if(nResult == 0) {
                printf( "\n[OUTPUT] 폴더 생성 성공\n" );
            }
            else if (nResult == -1) {
                perror( "[OUTPUT] 폴더 생성 실패 - 폴더가 이미 있거나 부정확함\n" );
                printf( "errorno : %d\n", errno );
            }
        }

        strcat(base_dir, "/HTTP");
        if (isDirectoryExists(base_dir) == 0) {
            int nResult = mkdir(base_dir, 0777);

            if(nResult == 0) {
                printf( "[HTTP] 폴더 생성 성공\n" );
            }
            else if (nResult == -1) {
                perror( "[HTTP] 폴더 생성 실패 - 폴더가 이미 있거나 부정확함\n" );
                printf( "errorno : %d\n", errno );
            }
        }
        
        strcat(base_dir, "/");
        strcat(base_dir, inet_ntoa(* (struct in_addr *) &receiver[my_port].dip));
        if (isDirectoryExists(base_dir) == 0) {
            int nResult = mkdir(base_dir, 0777);

            if(nResult == 0) {
                printf( "[ip] 폴더 생성 성공\n" );
            }
            else if (nResult == -1) {
                perror( "[ip] 폴더 생성 실패 - 폴더가 이미 있거나 부정확함\n" );
                printf( "errorno : %d\n", errno );
            }
        }

        char port[6] = {0, };
        snprintf(port, 6, "%u", my_port);
        strcat(base_dir, "/");
        strcat(base_dir, port);
        if (isDirectoryExists(base_dir) == 0) {
            int nResult = mkdir(base_dir, 0777);

            if(nResult == 0) {
                printf( "[port] 폴더 생성 성공\n" );
            }
            else if (nResult == -1) {
                perror( "[port] 폴더 생성 실패 - 폴더가 이미 있거나 부정확함\n" );
                printf( "errorno : %d\n", errno );
            }
        }

        strcat(base_dir, "/HEADER");
        if (isDirectoryExists(base_dir) == 0) {
            int nResult = mkdir(base_dir, 0777);

            if(nResult == 0) {
                printf( "[HEADER] 폴더 생성 성공\n" );
            }
            else if (nResult == -1) {
                perror( "[HEADER] 폴더 생성 실패 - 폴더가 이미 있거나 부정확함\n" );
                printf( "errorno : %d\n", errno );
            }
        }

        // goto base directory
        if (chdir(base_dir) == -1) {
            fprintf(stderr, "Cannot change working directory to base dir..\n");
            return;
        }

        printf("[REQUEST] call parsing_request : payload_size = %d\n", payload_size);
        if (payload_size > 0) {
            parsing_request(payload, payload_size, receiver, my_port);
        }

        // goto original directory
        if (chdir(curdir) == -1) {
            fprintf(stderr, "Cannot recover working directory to original..\n");
            return;
        }
    }
    // response packet
    else if (request_flag == 0) {
        printf("RESPONSE PACKET...\n");
        // filename 읽어와 해당 file에 data append
        char curdir[256] = {0, };
        if (getcwd(curdir, 256) == NULL) {
            printf("%s\n", curdir);
            fprintf(stderr, "Cannot save current directory\n");
            return;
        }

        char base_dir[256] = {0, };
        sprintf(base_dir, "./OUTPUT/HTTP/%s/%u", inet_ntoa(* (struct in_addr *) &receiver[my_port].dip), my_port);
        printf("base dir : %s\n", base_dir);

        // goto base directory
        if (chdir(base_dir) == -1) {
            fprintf(stderr, "Cannot change working directory to base dir..\n");
            return;
        }

        printf("[RESPONSE] call parsing_response : payload_size = %d\n", payload_size);
        if (payload_size > 0) {
            parsing_response(payload, payload_size, receiver, my_port);
        }

        // goto original directory
        if (chdir(curdir) == -1) {
            fprintf(stderr, "Cannot recover working directory to original..\n");
            return;
        }
    }
}




/* Seung Min Code End */
