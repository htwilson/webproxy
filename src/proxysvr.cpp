#include "functions.h"
#include "proxysvr.h"

//./myproxy listen_port forbidden_sites_file_path access_log_file_path
int main (int argc, char *argv[]) {

    //check that the user input the correct number of arguments
    if (argc != 4) {
        fprintf(stderr, "Error. Invalid number of arguments. Arguments are: listen_port forbidden_sites_file_path access_log_file_path\n");
        exit(EXIT_FAILURE);
    } 

    //check that the port # is correct
    checkPort(argv[1]);
    
    // check that both file paths are correct 
    checkPath(argv[2]);
    checkPath(argv[3]);
    
    //open socket here 
    int lstn_socket, conn_socket;
    struct sockaddr_in cli_addr, svr_addr;

    lstn_socket = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&svr_addr, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_addr.s_addr = INADDR_ANY;
    svr_addr.sin_port = htons(atoi(argv[1]));

    if ( (bind(lstn_socket, (struct sockaddr*) &svr_addr, sizeof(svr_addr))) < 0) {
		fprintf(stderr, "Bind error"); 
        exit(EXIT_FAILURE);
    }

    listen(lstn_socket, 50);

    //split the process here using threads, look at tcp echo server

    cout << "Success!" << endl;
    exit (EXIT_SUCCESS);
}