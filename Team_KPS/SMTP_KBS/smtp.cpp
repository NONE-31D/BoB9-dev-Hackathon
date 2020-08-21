#include "smtp.h"
/*
struct Server { 
	char *code[] = {"220"+0x20, "250"+0x20, "334"+0x20,
		"235"+0x20, "354"+0x20, "221"+0x20}; 
	double width = 1.0; 
};
*/
struct Client { 
	double length = 1.0; 
	double width = 1.0; 
};

void smtp_analysis(int port, u_char *payload, int length) {
	const char* state = "220";
	u_char* command;
	u_char* parameter;
	printf("<SMTP Paylod>\n");
	if (port == 587) {
		printf("Server\n");
		// Command 20 Parameter 0d 0a
		u_char cut = 0x20;
		for (u_int i=0; i<length; i++) {
	        
	        command[i] = payload[i];

	        printf("%02x ", payload[i]);
	    }	
	} else if (port == 3326) {
		printf("Client\n");
	}

	// print binary
	for (u_int i=0; i<length; i++) {
        // Start printing on the next after every 16 octets
        if ( (i % 16) == 0) {
            printf("\n0x%04x ", i);
        }
        // Print each octet as hex (x), make sure there is always two characters (.2).
        printf("%02x ", payload[i]);
    }
}