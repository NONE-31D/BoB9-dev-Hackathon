#ifndef _FTP_H
#define _FTP_H

#include "../stdafx.h"
//#include <cstdio>

extern int is_file_mining;
extern char file_name[500];


void ftp_analysis(u_char *payload, int payload_size);
void ftp_fileMining(u_char *payload, int payload_size);

#endif