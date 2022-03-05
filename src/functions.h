#pragma once
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <time.h>
#include <sys/time.h>
#include <math.h>
#include <fstream>
#include <vector>
#include <string.h>

using namespace std;

int nDigit(int n);
void checkPort(string str);
void checkPath(string str);
vector<string> getForbiddenDomains(string filepath);
string makeHTTPResponse(string status_code);
void printRFCTimestamp(string fp, string cli_ip, string f_line, int status_code, int size);
