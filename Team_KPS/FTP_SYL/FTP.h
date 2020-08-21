#include "../stdafx.h"

static int is_file_mining = 0;
static char file_name[500] = {0};

void ftp_analysis(u_char *payload, int payload_size);
void ftp_fileMining(u_char *payload, int payload_size);