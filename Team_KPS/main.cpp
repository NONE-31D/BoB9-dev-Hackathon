#include "stdafx.h"

int main(int argc, char *argv[])
{
    switch (argc) {
    case 3:
        if (strcmp(argv[1], "-t") == 0) {
            const char *interface = argv[2];
            traffic(interface);
        } else if (strcmp(argv[1], "-f") == 0) {
            const char *file = argv[2];
            pcap_f(file);
        } else {
            usage();
        }
        break;
    default:
        usage();
        return -1;
    }
}