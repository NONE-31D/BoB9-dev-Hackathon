#include "smtp.h"

void smtp_analysis(u_char *payload, int length) {
	for (u_int i=0; i<length; i++)
    {
        // Start printing on the next after every 16 octets
        if ( (i % 16) == 0) {
            printf("\n0x%04x ", i);
        }
        // Print each octet as hex (x), make sure there is always two characters (.2).
        printf("%02x ", payload[i]);
    }
}