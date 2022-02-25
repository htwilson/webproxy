all: server

server: src/proxysvr.cpp
	g++ -g -pthread -Wall src/funcs.cpp src/proxysvr.cpp -o bin/myproxy

clean:
	rm -f bin/myproxy