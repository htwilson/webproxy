#include "functions.h"
#include "proxysvr.h"

//COMMANDS
// wget 127.0.0.1:2039 --header="Host: pudim.com.br"
// curl -x http://127.0.0.1:2039/ http://www.example.com

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
    
    // open socket here for listening and connection 
    int lstn_sock, conn_sock;
    struct sockaddr_in cli_addr, svr_addr;
    socklen_t cli_len;

    lstn_sock = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&svr_addr, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;  //ipv4
    svr_addr.sin_addr.s_addr = INADDR_ANY; //localhost 127.0.0.1
    svr_addr.sin_port = htons(atoi(argv[1])); // port # 

    if ( (bind(lstn_sock, (struct sockaddr *) &svr_addr, sizeof(svr_addr))) < 0) {
		fprintf(stderr, "There was an error when calling bind(). Closing server.\n"); 
        exit(EXIT_FAILURE);
    }

    listen(lstn_sock, MAXREQ);

    vector<thread> threads; 

    while (true) {
        cli_len = sizeof(cli_addr);
        conn_sock = accept(lstn_sock, (struct sockaddr *) &cli_addr, &cli_len);

        //create the thread here, pass in forbidden domains vector 
        threads.push_back(thread(threadFunc, conn_sock, getForbiddenDomains(argv[2])));
    }
}

vector<string> getForbiddenDomains(string filepath) {
    vector<string> fb_domains;
    string line;
    ifstream fb_file;

    fb_file.open(filepath);

    if(!fb_file.is_open()) {
        fprintf(stderr, "Error opening forbidden domains file at PATH: /%s\n", filepath.c_str()); 
        exit(-1);
    }

    while(getline(fb_file, line)) {
        fb_domains.push_back(line);
    }

    return fb_domains;
}

void threadFunc(int conn_sock, vector<string> fb_domain) {
    // read the message from the client, create an ssl connection
    int n;
    char recvbuf[MAXSIZE];
    
    n = read(conn_sock, recvbuf, MAXSIZE);

    if (n < 0) {
        perror("Error");
        fprintf(stderr, "There was an issue calling read on a thread. Closing server.\n");
        exit(EXIT_FAILURE);
    }

    vector<string> parsed_req;
    //parse the request here. convert into a string  
    string str_req(recvbuf);

    int pos = 0;
    while ((pos = str_req.find("\n")) > -1) {
        parsed_req.push_back(str_req.substr(0, pos));
        str_req.erase(0, pos + strlen("\n"));
    }

    bool req_flag = false; 
    // bool dom_restr_flag = false;
    // bool port_flag = false;
    string domain;

    for (int i = 0; i < (int) parsed_req.size(); i++) {
        int index = 0;
        if ( (index = parsed_req[i].find("GET")) > -1 ) {
            req_flag = true;
        } else if ( (index = parsed_req[i].find("HEAD")) > -1 ) {
            req_flag = true;
        } else if ( (index = parsed_req[i].find("Host: ")) > -1 ) {
            domain = parsed_req[i].substr(6, parsed_req[i].size() - 7); //strip the newline char or else gethostbyname() will not work 
        }
    }
    //check the type of request, if not get or head, return 501
    if (!req_flag) {
        cout << "Send back 501 error." << endl;
    }

    //check that the requested domain is not in restricted files list, if is is, return 403 
    // https://stackoverflow.com/questions/32737083/extracting-ip-data-using-gethostbyname

    for (int i = 0; i < (int) fb_domain.size(); i++) {
        if (fb_domain[i].compare(domain) == 0) {
            cout << "return 403 forbidden domain name" << endl;
        }
    }

    struct hostent *he = gethostbyname(domain.c_str());
    struct in_addr a;

    if (he) {
        // printf("name: %s\n", he->h_name);
        // while (*he->h_aliases)
        //     printf("alias: %s\n", *he->h_aliases++);
        while (*he->h_addr_list)
        {
            bcopy(*he->h_addr_list++, (char *) &a, sizeof(a));
            // printf("address: %s\n", inet_ntoa(a));
        }
    } else {
        herror("error");
        cout << "return 404 domain not found" << endl;
    }

    for (int i = 0; i < (int) fb_domain.size(); i++) {
        if (fb_domain[i].compare(inet_ntoa(a)) == 0) {
            cout << "return 403, forbidden IP address" << endl;
        }
    }

    //check if there is a specifed port, if not, use 443, if 80, use 443 

    //check for errors in the HTTP request

    // print all requests to the access log file



    return; 
}

// NOTES:
// CONSIDER WHEN TO CLOSE THE CONNECTION SOCKET AND THE LISTENING SOCKET