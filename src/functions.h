#pragma once
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <time.h>
#include <sys/time.h>
#include <math.h>
using namespace std;

int nDigit(int n);
void checkPort(string str);
void checkPath(string str);
void printRFCTimestamp(string cli_ip, string f_line, string status_code, int size);