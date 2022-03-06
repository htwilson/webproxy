all: server

server: src/proxysvr.cpp
	g++ -g -pthread -Wall src/functions.cpp src/proxysvr.cpp -o bin/myproxy -lssl -lcrypto

clean:
	rm -f bin/myproxy && rm -r fileout/* 