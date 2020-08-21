#include "FTP.h"

int is_file_mining;

void ftp_analysis(u_char *payload, int payload_size){    
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

    printf(">>> FTP\tCommand : %s |args : %s\n", cmd, arg);
    
    if(is_file_mining == 1){
        if (!strcmp(cmd, "150")) is_file_mining = 2;
        return;
    } 

    if(is_file_mining = 2 && !strcmp(cmd, "226")){
        printf("[INFO] finish file mining ===>\n");
        is_file_mining = 0;
    }
        
    if(!strcmp(cmd, "RETR") || !strcmp(cmd, "STOR")) {
        is_file_mining = 1;
        printf("\n cmd %s detected\n", cmd);
    }

    memset(cmd, '\0', idx);
    memset(payload, '\0', payload_size);
    
}

void ftp_fileMining(u_char *payload, int payload_size){
    printf("yeah its time to mining!\n");
    
}