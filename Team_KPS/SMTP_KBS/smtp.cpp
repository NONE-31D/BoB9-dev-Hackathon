#include "smtp.h"

// 1: reading, 0: not reading
int smtp_reading;
// 1: go ahead, 0: default
int check;

int data_check;
int file_check;

char filename[50];
char file[5000000];
char file_tmp[5000000];

void smtp_analysis(int port, u_char *payload, int length) {
	int idx = split(payload, 0x20);
	char cmd[idx+1];
	strncpy(cmd, (char*)payload, idx);
	cmd[idx] = '\0';

	int idx2 = split(payload+idx+1, 0x0d);
	char parameter[idx2+1];
	strncpy(parameter, (char*)payload+idx+1, idx2);
	parameter[idx2] = '\0';	

	printf("idx: %d, idx2: %d\n", idx, idx2);

	printf("<SMTP Paylod>\n");
	if (port == 587) {
		printf("Server\n");
		result_document(payload, length);
		
	    if (!strcmp(cmd, "354")) {
	    	smtp_reading = 1;
	    	check = 1;
	    }

	    if (!strcmp(cmd, "250") && check == 1) {
	    	result_file();
	    	smtp_reading = 0;
	    	data_check = 0;
	    	file_check = 0;
	    }
	
	} else if (port == 3326) {
		printf("Client\n");

		int f_cnt=0;
		if(smtp_reading == 1 && check ==1) {
			data_check++;
			if (data_check == 1){
				result_document(payload, length);

				for (int i=0; i<length; i++) {
					if (memcmp(&payload[i], "filename=\"", 10) == 0) {
						for (int j=10; j<21; j++) {
							filename[f_cnt] = payload[i+j];
							f_cnt++;
						}
						printf("%s\n", filename);
						printf("====Binary====\n");
						sprintf(file, "%s%s", file, &payload[i+26]);
					}
				}
			} else {
				printf("====Binary====\n");
				sprintf(file, "%s%s", file, payload);
			}
	    }
	}
	memset(cmd, '\0', idx);
    memset(parameter, '\0', idx2);
}

void result_file(){
	char *ptr;
	ptr = strtok(file, "\r\n");
	while (ptr != NULL) {
		sprintf(file_tmp, "%s%s", file_tmp, ptr);
		ptr = strtok(NULL, "\r\n");
	}
	char tmp[100] = "./SMTP_KBS/";
	strcat(tmp, filename);
	FILE *fp = fopen(tmp, "ab+");
	fwrite(file_tmp, strlen(file_tmp), 1, fp);
	fclose(fp);
}

void result_document(u_char *payload, int length){
	FILE *fp = fopen("./SMTP_KBS/smtp_document", "ab+");
	fwrite(payload, length, 1, fp);
	fclose(fp);
}

int split(u_char *payload, int find) {
	char curr;
	int idx = 0;
	do {
        curr = *(payload+idx);
        if(curr == find) break;
        idx++;
    } while(curr);

    return idx;
}