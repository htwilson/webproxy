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
    vector<string> fb_domains = getForbiddenDomains(argv[2]);

    while (true) {
        cli_len = sizeof(cli_addr);
        conn_sock = accept(lstn_sock, (struct sockaddr *) &cli_addr, &cli_len);

        // get the client IP address
        string cli_addr_str(inet_ntoa(cli_addr.sin_addr));
        // cout << "Cli addr: " << cli_addr_str << endl;

        //create the thread here, pass in forbidden domains vector 
        threads.push_back(thread(threadFunc, conn_sock, fb_domains, argv[3], cli_addr_str));
    }
}

void threadFunc(int conn_sock, vector<string> fb_domain, string access_log_fp, string cli_addr_str) {
    // read the message from the client, create an ssl connection
    int n;
    char recvbuf[MAXSIZE];
    
    n = read(conn_sock, recvbuf, MAXSIZE);

    if (n < 0) {
        fprintf(stderr, "There was an issue calling read on a thread.\n");
        //terminate the thread
        // exit(EXIT_FAILURE);
        close(conn_sock);
        return; 
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
    string domain;
    string port = "443";

    //check if there is a specifed port, if not, use 443, if 80, use 443 
    //check the type of HTTP request as well
    for (int i = 0; i < (int) parsed_req.size(); i++) {
        int index = 0;
        if ( (index = parsed_req[i].find("GET")) > -1 ) {
            if ( (index = parsed_req[i].rfind(":")) > -1 ) {
                port = parsed_req[i].substr(index + 1);
                index = port.find(" ");
                port = port.substr(0, index - 1);
            }
            req_flag = true;
        } else if ( (index = parsed_req[i].find("HEAD")) > -1 ) {
            if ( (index = parsed_req[i].rfind(":")) > -1 ) {
                port = parsed_req[i].substr(index + 1);
                index = port.find(" ");
                port = port.substr(0, index - 1);
            }
            req_flag = true;
        } else if ( (index = parsed_req[i].find("Host: ")) > -1 ) {
            domain = parsed_req[i].substr(6, parsed_req[i].size() - 7); //strip the newline char or else gethostbyname() will not work 
        }
    }

    //check the type of request, if not get or head, return 501
    if (!req_flag) {
        string msg = makeHTTPResponse("501");
        printRFCTimestamp(access_log_fp, cli_addr_str, parsed_req[0], "501", 0);
        cout << msg << endl;
        if (send(conn_sock, msg.c_str(), msg.size(), 0) < 0) {
            fprintf(stderr, "There was an error when sending. \n");
        }
        close(conn_sock);
        return; 
    }

    //check that the requested domain is not in restricted files list, if is is, return 403 
    for (int i = 0; i < (int) fb_domain.size(); i++) {
        if (fb_domain[i].compare(domain) == 0) {
            string msg = makeHTTPResponse("403");
            printRFCTimestamp(access_log_fp, cli_addr_str, parsed_req[0], "403", 0);
            cout << msg << endl;
            if (send(conn_sock, msg.c_str(), msg.size(), 0) < 0) {
                fprintf(stderr, "There was an error when sending. \n");
            }
            close(conn_sock);
            return; 
        }
    }

    // https://stackoverflow.com/questions/32737083/extracting-ip-data-using-gethostbyname
    struct hostent *host_entry = gethostbyname(domain.c_str());
    struct in_addr addr;

    if (!host_entry) {
        // DNS was not able to find an address
        // herror("error");
        string msg = makeHTTPResponse("400");
        printRFCTimestamp(access_log_fp, cli_addr_str, parsed_req[0], "400", 0);
        cout << msg << endl;
        if (send(conn_sock, msg.c_str(), msg.size(), 0) < 0) {
            fprintf(stderr, "There was an error when sending. \n");
        }
        close(conn_sock);
        return; 
    }

    while (*host_entry->h_addr_list) {
        bcopy(*host_entry->h_addr_list++, (char *) &addr, sizeof(addr));
    }

    // cout << "DNS: " << inet_ntoa(addr) << endl;
    // cout << "thread IP addr: " << cli_addr_str << endl;
    // print all requests to the access log file
    printRFCTimestamp(access_log_fp, cli_addr_str, parsed_req[0], "200", 0);
    return; 
}

// NOTES:
// CONSIDER WHEN TO CLOSE THE CONNECTION SOCKET AND THE LISTENING SOCKET

//SSL methods to use:
// SSLv23_client_method()