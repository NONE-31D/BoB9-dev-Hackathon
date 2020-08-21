#pragma once
#include <string>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <map>

void smtp_analysis(int port, u_char *payload, int length);
