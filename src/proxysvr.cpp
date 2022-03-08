#include "functions.h"
#include "proxysvr.h"

mutex glock;
vector<string> fb_domains; 
string fb_filepath;

//COMMANDS & NOTES
// wget www.example.com -e use_proxy=yes -e http_proxy=127.0.0.1:2039
// curl -x http://127.0.0.1:2039/ http://www.example.com
// ctrl-z to stop server, kill -9 $(jobs -p) to kill process
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

    //set the forbidden domains to a global variable
    fb_filepath = argv[2];
    
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

    // call the signal handler to reload the forbidden list file
    // https://www.tutorialspoint.com/how-do-i-catch-a-ctrlplusc-event-in-cplusplus
    signal(SIGINT, signalHandler);

    // ignore SIGPIPE SIGNAL ON TCP SERVERS
    // https://openssl-users.openssl.narkive.com/Qshv9fpx/ssl-shutdown-and-sigpipe
    // https://stackoverflow.com/questions/18935446/program-received-signal-sigpipe-broken-pipe
    signal(SIGPIPE, SIG_IGN);
 
    fb_domains = getForbiddenDomains(fb_filepath);

    while (true) {
        cli_len = sizeof(cli_addr);
        if ( (conn_sock = accept(lstn_sock, (struct sockaddr *) &cli_addr, &cli_len)) < 0) {
		    fprintf(stderr, "There was an error accepting a connecting socket\n"); 
            continue;
        }
        // get the client IP address
        string cli_addr_str(inet_ntoa(cli_addr.sin_addr));

        //create the thread here, pass in threadFunc args
        thread(threadFunc, conn_sock, argv[3], cli_addr_str).detach();
    }
}

// handle SIGINT by locking threads and updating fb_domains
void signalHandler(int signum) {
    glock.lock();
    fb_domains = getForbiddenDomains(fb_filepath);
    glock.unlock();
    return;
}

void threadFunc(int conn_sock, string access_log_fp, string cli_addr_str) {
    // read the message from the client, create an ssl connection
    char recvbuf[MAXSIZE];
    if (read(conn_sock, recvbuf, MAXSIZE) < 0) {
        fprintf(stderr, "There was an issue calling read on a thread. Closing thread.\n");
        close(conn_sock);
        return; 
    }

    //parse the request here. convert rcvbuf into a string 
    vector<string> parsed_req; 
    string str_req(recvbuf);

    int pos = 0;
    while ( (pos = str_req.find("\n")) > -1) {
        //cout << str_req.substr(0, pos) << endl;
        parsed_req.push_back(str_req.substr(0, pos));
        str_req.erase(0, pos + strlen("\n"));
    }

    bool req_flag = false; 
    bool header_only = NULL; 
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
            header_only = false;
            req_flag = true;
        } else if ( (index = parsed_req[i].find("HEAD")) > -1 ) {
            if ( (index = parsed_req[i].rfind(":")) > -1 ) {
                port = parsed_req[i].substr(index + 1);
                index = port.find(" ");
                port = port.substr(0, index - 1);
            }
            header_only = true;
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
        printRFCTimestamp(access_log_fp, cli_addr_str, parsed_req[0], 501, 0);
        cout << msg << endl;
        if (send(conn_sock, msg.c_str(), msg.size(), 0) < 0) {
            fprintf(stderr, "There was an error when sending in a thread. Closing thread.\n");
        }
        close(conn_sock);
        return; 
    }

    //check that the requested domain is not in restricted files list, if is is, return 403 
    for (int i = 0; i < (int) fb_domains.size(); i++) {
        if (fb_domains[i].compare(domain) == 0) {
            string msg = makeHTTPResponse("403");
            printRFCTimestamp(access_log_fp, cli_addr_str, parsed_req[0], 403, 0);
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
        string msg = makeHTTPResponse("400");
        printRFCTimestamp(access_log_fp, cli_addr_str, parsed_req[0], 400, 0);
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

    int ssl_sock;
    // create a new socket to send to the destination 
    if ( (ssl_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "There was an issue creating a socket on the thread. Closing thread.\n"); 
        close(conn_sock);
        return;
    } 

    // https://stackoverflow.com/questions/1543466/how-do-i-change-a-tcp-socket-to-be-non-blocking
    if ( fcntl(conn_sock, F_SETFL, fcntl(conn_sock, F_GETFL, 0) | O_NONBLOCK) < 0){
        fprintf(stderr, "There was an issue making a socket non blocking. Closing thread.\n"); 
        close(conn_sock);
        return;
    }

    // create the dst address struct    
    struct sockaddr_in dst_addr;
    bzero(&dst_addr, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(atoi(port.c_str()));

    // validate ip address
    if (inet_pton(AF_INET, inet_ntoa(addr), &dst_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP address %s. \n", inet_ntoa(addr));
        close(ssl_sock);
        close(conn_sock);
        return;
    }

    //connect to the dst
    if (connect(ssl_sock, (struct sockaddr *) &dst_addr, sizeof(dst_addr)) < 0) {
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

    //create CTX
    SSL_CTX *ctx = SSL_CTX_new( SSLv23_client_method()); 
    if (!ctx) {
        fprintf(stderr, "Error creating SSL. Terminating thread.\n");
        close(ssl_sock);
        close(conn_sock);
        return;
    }

    //create SSL structure
    SSL *ssl = SSL_new (ctx);
    if (!ssl) {
        fprintf(stderr, "Error creating SSL. Terminating thread.\n");
        SSL_CTX_free(ctx);
        close(ssl_sock);
        close(conn_sock);
        return;
    }

    // connect the SSL object to the socket
    if (SSL_set_fd (ssl, ssl_sock) < 0) {
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
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "Error connecting using SSL. Terminating thread.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(ssl_sock);
        close(conn_sock);
        return;
    }

    //write to destination
    if (SSL_write(ssl, recvbuf, MAXSIZE) <= 0) {
        fprintf(stderr, "Error writing over SSL socket. Terminating thread.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(ssl_sock);
        close(conn_sock);
        return;
    }

    // clear the buffer of the client request
    memset(recvbuf, 0, MAXSIZE);

    // NOTE: THE FIRST READ WILL RETRIEVE THE HEADER, THEN SUBSEQUENT READS WILL GET DATA 
    // read header from destination 
    int r; 
    if ( (r = SSL_read(ssl, recvbuf, MAXSIZE)) <= 0) {
        fprintf(stderr, "Error writing over SSL socket. Terminating thread.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(ssl_sock);
        close(conn_sock);
        return;
    }

    cout << recvbuf << endl;
    int http_status;
    string content_size;
    string recvstr(recvbuf);
    pos = 0;

    // Obtain the content length and status code from the header
    while ( (pos = recvstr.find("\n")) > -1) {
        string header_line = recvstr.substr(0, pos);
        if ( ((int) header_line.find("Content-Length: ")) > -1 ) {
            int index = header_line.find(" ");
            content_size = header_line.substr(index + 1, header_line.size() - index + 1);
        } else if ( ((int) header_line.find("HTTP")) > -1 ) {
            int index = header_line.find(" ");
            http_status = atoi((header_line.substr(index + 1, header_line.size() - index + 1)).c_str());
        }
        recvstr.erase(0, pos + strlen("\n"));
    }

    // cout << "Bytes read: " << r << endl;
    // cout << content_size << endl;
    //print to the access log here 
    printRFCTimestamp(access_log_fp, cli_addr_str, parsed_req[0], http_status, atoi(content_size.c_str()));

    // forward the header to the client
    if (send(conn_sock, recvbuf, r, 0) < 0) {
        fprintf(stderr, "There was an error when sending to client. Terminating thread.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(ssl_sock);
        close(conn_sock);
        return;
    }
    
    // if header_only is disabled, call read, and start sending data to the client 
    if (!header_only) {
        //reset the recv buffer
        memset(recvbuf, 0, MAXSIZE);
        int bytes_read = 0;
        bool reset_flag = false; 
        while (true) {

            // if the content length exists, you can read until you get the amount 
            if (bytes_read >= atoi(content_size.c_str()) && atoi(content_size.c_str()) != 0) {
                break;
            }

            // if the file is reloaded and the domain is now restricted, break from the loop
            // close sockets, client will reconnect, 403 will be sent back
            for (int i = 0; i < (int) fb_domains.size(); i++) {
                if (fb_domains[i].compare(domain) == 0) {
                    reset_flag = true;
                }
            }   

            if (reset_flag) {
                break;
            }

            r = SSL_read(ssl, recvbuf, MAXSIZE);

            bytes_read += r;
            //cout << "Bytes read: " << bytes_read << " total size: " << content_size << endl;
            //cout << recvbuf << endl;

            int err = SSL_get_error(ssl, r); 
            //cout << r << endl;
            //cout << err << endl; 
            if (err != 0) {
                //socket error, break the connection and restart 
                break;
            }
            // if (err == SSL_ERROR_ZERO_RETURN) {
            //     cout << "ZERO RETURN" << endl;
            //     break;
            // } else if (err == SSL_ERROR_WANT_READ) {
            //     cout << "WANT READ" << endl;
            // } else if (err == SSL_ERROR_WANT_WRITE) {
            //     cout << "WANT WRITE" << endl;
            // } else if (err == SSL_ERROR_SSL) {
            //     cout << "ERROR SSL" << endl;
            // } else if (err == SSL_ERROR_SYSCALL) {
            //     break;
            // }

            if (err == 0) {
                if (send(conn_sock, recvbuf, r, 0) < 0) {
                    // if the socket we are writing to has been closed by the client
                    if (errno == ECONNRESET) {
                        puts("client termination");
                        break;
                    }
                    fprintf(stderr, "There was an error when sending to client. Terminating thread.\n");
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    SSL_CTX_free(ctx);
                    close(ssl_sock);
                    close(conn_sock);
                    return;
                }
            }
        }
    }

    // ssl cleanip here before return, close sockets
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(ssl_sock);
    close(conn_sock);
    return; 
}

//TO-DO:
// Signal to reload the file - COMPLETE
// Chunked encoding - COMPlETE
// closing threads - COMPLETE
// multiple clients - COMPLETE
// specified port numbers