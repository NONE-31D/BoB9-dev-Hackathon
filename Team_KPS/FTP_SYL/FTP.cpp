#include "FTP.h"

void ftp_analysis(u_char *payload, int payload_size){    
    

    printf("\n>> FTP\t\t|Command : %s |args : %s end", cmd, arg);
    
    if(is_file_mining == 1){
        if (!strcmp(cmd, "150")) is_file_mining = 2;
    } 
        
    if(!strcmp(cmd, "RETR") || !strcmp(cmd, "STOR")) {
        is_file_mining = 1;
        printf("\n cmd %s detected\n", cmd);
    }

    memset(cmd, '\0', idx);
    memset(payload, '\0', payload_size);
    
}

void ftp_fileMining(u_char *payload, int payload_size){
    
}