#pragma once
#include <string>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <stdlib.h>
#include <pcap.h>

void smtp_analysis(int port, u_char *payload, int length);
int split(u_char *payload, int find);
