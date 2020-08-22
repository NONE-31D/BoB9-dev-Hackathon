#include "FTP.h"

int is_file_mining;
char file_name[500];

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
    printf("payload>>>\n%s", payload);
    FILE *fp = fopen(file_name, "ab+");
    fwrite(payload, payload_size, 1, fp);
    fclose(fp);
}