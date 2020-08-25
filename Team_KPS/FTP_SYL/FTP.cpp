#include "FTP.h"

int is_file_mining;
char file_name[500];

void ftp_analysis(u_char *payload, int payload_size, Protocols protocols){    
    char curr;
    int idx = 0;
    
    // strstr func
    // split by space. just find index of space. 
    do {
        curr = *(payload+idx);
        if(curr == 0x20) break;
        idx++;
    } while(curr);

    char cmd[idx+1];
    strncpy(cmd, (char*)payload, idx);
    cmd[idx] = '\0';

    u_char* arg_start = payload+idx+1;
    idx = 0;
    do {
        curr = *(arg_start + idx);
        if(curr == 0x0D) break;
        idx++;
    } while(curr);

    char arg[idx+1];
    strncpy(arg, (char*)arg_start, idx);
    arg[idx] = '\0';


    protocols.proto = "FTP";
    protocols.cmd = cmd;
    protocols.argv = arg;

    Value Log;
    Log["protocol"] = protocols.proto;
    
    Value MAC;
    char smac_str[30];
    char dmac_str[30];
    protocols.print_mac(protocols.smac, smac_str);
    protocols.print_mac(protocols.dmac, dmac_str);
    MAC["src"] = smac_str;
    MAC["dst"] = dmac_str;

    Log["MAC"] = MAC;

    Value IP;
    char sip_str[16], dip_str[16];
    protocols.print_ip(protocols.ip_src, sip_str);
    protocols.print_ip(protocols.ip_dst, dip_str);
    IP["src"] = sip_str;
    IP["dst"] = dip_str;

    Log["IP"] = IP;

    Value TCP;
    TCP["src port"] = ntohs(protocols.sport);
    TCP["dst port"] = ntohs(protocols.dport);

    Log["TCP"] = TCP;

    Value FTP;
    FTP["cmd"] = protocols.cmd;
    FTP["arg"] = protocols.argv;

    Log["FTP"] = FTP;

    Json::StyledWriter writer;
    string str = writer.write(Log);
 
    std::ofstream json_file("log_ftp.json", ios::app);
    json_file << str;

    printf(">>> FTP\tCommand : %s |args : %s\n", cmd, arg);
    
    if(is_file_mining == 1){
        if (!strcmp(cmd, "150")) is_file_mining = 2;
        printf("[INFO] Start File Mining, %s\n", file_name);
        return;
    } 

    if(is_file_mining = 2 && !strcmp(cmd, "226")){
        printf("[INFO] finish file mining ===> %s\n", file_name);
        is_file_mining = 0;
    }
        
    if(!strcmp(cmd, "RETR") || !strcmp(cmd, "STOR")) {
        is_file_mining = 1;
        printf("\n cmd %s detected\n", cmd);
        strcpy(file_name, arg);
    }

    memset(cmd, '\0', idx);
    memset(payload, '\0', payload_size);

}

void ftp_fileMining(u_char *payload, int payload_size){
    // printf("payload>>>\n%s", payload);
    FILE *fp = fopen(file_name, "ab+");
    fwrite(payload, payload_size, 1, fp);
    fclose(fp);
}