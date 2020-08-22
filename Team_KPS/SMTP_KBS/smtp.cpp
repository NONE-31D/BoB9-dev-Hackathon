#include "smtp.h"

// 1: reading, 0: not reading
int smtp_reading;
// 1: go ahead, 0: default
int check;

int data_check;
int file_check;

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
      printf("Command: %s\n", cmd);
      printf("Parameter: %s\n", parameter);
      
       if (!strcmp(cmd, "354")) {
          smtp_reading = 1;
          check = 1;
       }

       if (!strcmp(cmd, "250") && check == 1) {
          smtp_reading = 0;
          data_check = 0;
          file_check = 0;
       }
   
   } else if (port == 3326) {
      printf("Client\n");
      printf("Command: %s\n", cmd);
      printf("Parameter: %s\n", parameter);

      if(smtp_reading == 1 && check ==1) {
         data_check++;
         if (data_check == 1){
            //FILE *fp = fopen(smtp_file, "ab+");
            for (int i=0; i < length; i++) {
               if (payload[i] == 0x65 && payload[i+1] == 0x4a && payload[i+2] == 0x38 && payload[i+3] == 0x2b)
                  file_check = 1;
               if (file_check == 1) {
                  //fwrite(payload[i], 1, 1, fp);
                  if ( (i % 16) == 0) {
                        printf("\n0x%04x ", i);
                    }
                  printf("%02x ", payload[i]);
               } else {
                  printf("%c", payload[i]);
               }
               if (payload[i] == 0x0d && payload[i] == 0x0a) {
                  i += 2;
                  printf("\n");
               }
            }
            //fclose(fp);
         } else {
            //FILE *fp = fopen(smtp_file, "ab+");
            for (int i=0; i < length; i++) {
               //fwrite(payload[i], 1, 1, fp);
                  if ( (i % 16) == 0) {
                        printf("\n0x%04x ", i);
                    }
               printf("%02x ", payload[i]);
               if (payload[i] == 0x0d && payload[i] == 0x0a) {
                  i += 2;
                  printf("\n");
               }
            }
            //fclose(fp);
         }
       }
   }
   memset(cmd, '\0', idx);
    memset(parameter, '\0', idx2);
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