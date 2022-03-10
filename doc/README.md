# lab4cpp
#############################################################################
# Hugo Wilson
# huwilson@ucsc.edu
# ID #1599321
# 3/9/2022
#############################################################################

				            FINAL PROJECT README
/src/proxysvr.cpp
C++ program that acts as a proxy server that will convert HTTP messages to 
HTTPS messages. Any response from the destination will be sent to the proxy
via HTTPS then sent back to the client over the HTTP connection. The server 
is able to support concurrent requests through the use of threading. The 
arguments for the program are portnum, forbiddensitesfilepath, and 
accesslogfilepath. forbiddensitesfilepath must already exist, but 
accesslogfilepath will be constructed if it does not already exist. The 
proxy can send various HTTP codes based on bad requests, forbidden domains
server errors, and disconnects to the destination web server. 

/src/proxysvr.h
Header file for proxysvr.cpp that defines various functions, macros, and
includes that will be used in the server application. 

/src/functions.cpp
C program that contains helper functions that are used in the proxy. 

/src/functions.h
Header file for functions.cpp that defines various functions, macros, and
includes that will be used in the server application. 

/doc/DOCX.txt
This file is the documentation for the final project. It contains a run down
of how the program works, some test cases and that were used to determine its
effectiveness, and a synopsis of some shortcomings that the implementation 
may have.

/makefile
A makefile that will compile the program from the src directory and place the
executable in the bin folder. Make clean will remove the executable.