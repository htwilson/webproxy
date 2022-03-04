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

    if ( (lstn_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "There was an error creating the listening socket. Closing server\n"); 
        exit(EXIT_FAILURE);
    }

    bzero(&svr_addr, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;  //ipv4
    svr_addr.sin_addr.s_addr = INADDR_ANY; //localhost 127.0.0.1
    svr_addr.sin_port = htons(atoi(argv[1])); // port # 

    if ( bind(lstn_sock, (struct sockaddr *) &svr_addr, sizeof(svr_addr)) < 0) {
		fprintf(stderr, "There was an error when calling bind(). Closing server.\n"); 
        exit(EXIT_FAILURE);
    }

    if ( listen(lstn_sock, MAXREQ) < 0) {
		fprintf(stderr, "There was an error when calling listen(). Closing server.\n"); 
        exit(EXIT_FAILURE);
    }

    vector<thread> threads; 
    vector<string> fb_domains = getForbiddenDomains(argv[2]);

    while (true) {
        cli_len = sizeof(cli_addr);
        if ( (conn_sock = accept(lstn_sock, (struct sockaddr *) &cli_addr, &cli_len)) < 0) {
		    fprintf(stderr, "There was an error accepting a connecting socket\n"); 
            continue;
        }
        // get the client IP address
        string cli_addr_str(inet_ntoa(cli_addr.sin_addr));

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
        fprintf(stderr, "There was an issue calling read on a thread. Closing thread.\n");
        close(conn_sock);
        return; 
    }

    vector<string> parsed_req;
    //parse the request here. convert into a string  
    string str_req(recvbuf);

    int pos = 0;
    while ((pos = str_req.find("\n")) > -1) {
        //cout << str_req.substr(0, pos) << endl;
        parsed_req.push_back(str_req.substr(0, pos));
        str_req.erase(0, pos + strlen("\n"));
    }

    bool req_flag = false; 
    string domain;
    string port;
    //check if there is a specifed port, if not, use 443, if 80, use 443 
    //check the type of HTTP request as well
    for (int i = 0; i < (int) parsed_req.size(); i++) {
        int index = 0;
        // cout << parsed_req[i] << endl;
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

    //make sure that the port is found, must pass atoi, if 0, it was not a number or if 80, set to 443
    if (atoi(port.c_str()) <= 0 || atoi(port.c_str()) == 80) {
        port = "443";
    }

    //check the type of request, if not get or head, return 501
    if (!req_flag) {
        string msg = makeHTTPResponse("501");
        printRFCTimestamp(access_log_fp, cli_addr_str, parsed_req[0], "501", 0);
        cout << msg << endl;
        if (send(conn_sock, msg.c_str(), msg.size(), 0) < 0) {
            fprintf(stderr, "There was an error when sending in a thread. Closing thread.\n");
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
                fprintf(stderr, "There was an error when sending in a thread. Closing thread.\n");
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
            fprintf(stderr, "There was an error when sending in a thread. Closing thread.\n");
        }
        close(conn_sock);
        return; 
    }

    while (*host_entry->h_addr_list) {
        bcopy(*host_entry->h_addr_list++, (char *) &addr, sizeof(addr));
    }

    int ssl_sock/*, sock_two*/;
    // create a new socket to send to the destination 
    if ( (ssl_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "There was an issue creating a socket on the thread. Closing thread.\n"); 
        close(conn_sock);
        return;
    } 

    // create the dst address struct    
    struct sockaddr_in dst_addr;
    bzero(&dst_addr, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    // cout << "PORT: " << port << endl;
    dst_addr.sin_port = htons(atoi(port.c_str()));

    // validate ip address
    if ( inet_pton(AF_INET, inet_ntoa(addr), &dst_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP address %s. \n", inet_ntoa(addr));
        close(ssl_sock);
        close(conn_sock);
        return;
    }

    //connect to the dst
    if ( connect(ssl_sock, (struct sockaddr *) &dst_addr, sizeof(dst_addr)) < 0) {
        fprintf(stderr, "Connection error. Incorrect port or IP address? \n");
        close(ssl_sock);
        close(conn_sock);
        return;
    }

    // initialize SSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // https://stackoverflow.com/questions/7698488/turn-a-simple-socket-into-an-ssl-socket
    // https://stackoverflow.com/questions/41229601/openssl-in-c-socket-connection-https-client
    //create SSL structure and CTX
    SSL_CTX *ctx = SSL_CTX_new( SSLv23_client_method()); //change from server method because it is not acting as the server 
    SSL *ssl = SSL_new (ctx);
    if (!ssl) {
        fprintf(stderr, "Error creating SSL. Terminating thread.\n");
        //log_ssl();
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(ssl_sock);
        close(conn_sock);
        return;
    }
    // if ( (ssl_sock = SSL_get_fd(ssl)) < 0) {
    //     fprintf(stderr, "Error linking socket to SSL. Terminating thread.\n");
    //     SSL_shutdown(ssl);
    //     SSL_free(ssl);
    //     close(ssl_sock);
    //     close(conn_sock);
    //     return;
    // }

    // connect the SSL object to the socket
    if ( SSL_set_fd (ssl, /*sock_two*/ssl_sock) < 0) {
        fprintf(stderr, "Error connecting SSL to the socket. Terminating thread.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(ssl_sock);
        close(conn_sock);
        return;
    }

    //verify the SSL connection 
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    //connect using ssl
    // there is an error here 
    if ( (SSL_connect(ssl)) <= 0) {
        fprintf(stderr, "Error connecting using SSL. Terminating thread.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(ssl_sock);
        close(conn_sock);
        return;
    }

    //write to destination 
    if ( SSL_write(ssl, recvbuf, MAXSIZE) <= 0) {
        fprintf(stderr, "Error writing over SSL socket. Terminating thread.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(ssl_sock);
        close(conn_sock);
        return;
    }
    memset(recvbuf, 0, MAXSIZE);
    // read from destination 
    if ( SSL_read(ssl, recvbuf, MAXSIZE) <= 0) {
        fprintf(stderr, "Error writing over SSL socket. Terminating thread.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(ssl_sock);
        close(conn_sock);
        return;
    }
    cout << "Recieved from SSL! " << recvbuf << endl;

    string content_size;
    string recvstr(recvbuf);
    // int index = recvstr.find("Content-Length: ");
    // int end = recvstr.fi
    // content_size = recvstr.substr(index, )

    pos = 0;
    while ( (pos = recvstr.find("\n")) > -1) {
        int index;
        // cout << recvstr.substr(0, pos) << endl;
        if ( ((int) recvstr.substr(0, pos).find("Content-Length: ")) > -1 ) {
            index = recvstr.substr(0, pos).find(" ");
            int end = recvstr.substr(0, pos).find("\n");
            content_size = recvstr.substr(index + 1, end);
        }
        recvstr.erase(0, pos + strlen("\n"));
    }
    printRFCTimestamp(access_log_fp, cli_addr_str, parsed_req[0], "200", atoi(content_size.c_str()));
    return; 
}

// NOTES:
// CONSIDER WHEN TO CLOSE THE CONNECTION SOCKET AND THE LISTENING SOCKET

//SSL methods to use:
// SSLv23_client_method()