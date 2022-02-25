#include "topheader.h"

//helper function to determine the number of digits in a given integer, for use in checkPort()
// store the datagrams somewhere and reorder them 
int nDigit(int n) {
  int count = 0;
  while (n != 0) {
    n /= 10;
    count++;
  }
  return count;
} 

//helper function that validates that the port is a correct integer
void checkPort(string str) {
    //Possibility that port number may be 0, and atoi returns 0 if not a digit, taken into consideraton
    int port = atoi(str.c_str());
    int digits = nDigit(port);
        
    //checks that the port is an integer by comparing number of digits to string length 
    if (((int) str.size() != digits || (str.compare("") == 0)) && (str.compare("0") != 0)) {
        fprintf(stderr, "Port number '%s' is not a positive integer value or may be missing port number after colon. Acceptable range: [1024:65535]. \n", str.c_str());
        exit(-1);
    }
    //checks that the port is in a valid range 
    if (port < 1024 || port > 65535) {
        fprintf(stderr, "Invalid port number '%d'. Acceptable range: [1024:65535]. \n", port);
        exit(-1);
    }
}

void checkPath(string str) {
    if ((int)str.find("//") != -1) {
        fprintf(stderr, "Invalid root_file_path specified. No // allowed.\n");
        exit(-1);
    } else if ((int)str.find("/") == 0) {
        fprintf(stderr, "Invalid root_file_path specified. Remove / at beginning.\n");
        exit(-1);
    } else if (str.rfind("/") == str.size() - 1) {
        fprintf(stderr, "Invalid root_file_path specified. Remove / at end.\n");
        exit(-1);
    } else if ((int)str.find("\\") != -1) {
        fprintf(stderr, "Invalid root_file_path specified. No \\ allowed.\n");
        exit(-1);
    }
}

// https://stackoverflow.com/questions/3673226/how-to-print-time-in-format-2009-08-10-181754-811
// date_format client_ip request_first_line http_status_code object_size_in_byte
void print_rfc_timestamp(string cli_ip, string f_line, string status_code, int size) {
    time_t timer;
    char buffer[26];
    char str_ms[20];
    struct tm* tm_ptr;
    struct timeval tv;

    timer = time(NULL);
    tm_ptr = gmtime(&timer);
    gettimeofday(&tv, NULL);
    
    strftime(buffer, 26, "%Y-%m-%dT%H:%M:%S", tm_ptr);
    //convert ms to string and truncate
    sprintf(str_ms, "%ld", tv.tv_usec);

    fprintf(stdout, "%s.%.3sZ", buffer, str_ms);
    // date_format client_ip request_first_line http_status_code object_size_in_byte
    fprintf(stdout, " %s, %s, %s, %d\n", cli_ip.c_str(), f_line.c_str(), status_code.c_str(), size);
}
