#pragma once
#include <thread> 
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAXSIZE 32678
#define MAXREQ 50

using namespace std;

void threadFunc(int conn_sock, vector<string> fb_domain, string access_log_fp, string cli_addr_str);