#include "proxysvr.h"

//./myproxy listen_port forbidden_sites_file_path access_log_file_path
int main (int argc, char *argv[]) {

    //check that the user input the correct number of arguments
    if (argc != 4) {
        fprintf(stderr, "Error. Invalid number of arguments.\n");
        exit(EXIT_FAILURE);
    } 

    //check that the port # is correct
    checkPort(argv[1]);
    
    // check that both file paths are correct 
    checkPath(argv[2]);
    checkPath(argv[3]);

    //open socket here 
    cout << "Success!" << endl;
    exit (EXIT_SUCCESS);
}