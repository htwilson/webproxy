#pragma once
#include <thread> 
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>
#include <fstream>
#include <netdb.h>

#define MAXSIZE 32678
#define MAXREQ 50

using namespace std;

void threadFunc(int conn_sock, vector<string> fb_domain);
vector<string> getForbiddenDomains(string filepath);