#pragma once
#include <thread>
#include <mutex>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <fcntl.h>

#define MAXSIZE 1500
#define MAXREQ 50

using namespace std;

void signalHandler(int signum);
void threadFunc(int conn_sock, string access_log_fp, string cli_addr_str);
void sendHTTPResponse(int sockfd, string status_code);
void writeToLog(string fp, string cli_ip, string f_line, int status_code, int size);