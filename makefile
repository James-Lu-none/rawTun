CXX = x86_64-w64-mingw32-g++
CXXFLAGS = -Wall -O2 -std=c++11 -static
HOST_CXX ?= g++

all: client server

client: client.exe

client.exe: client.cpp wintun.h protocol.h
	$(CXX) $(CXXFLAGS) -o $@ $< -lws2_32 -liphlpapi

server: gateway-server

gateway-server: server.cpp protocol.h
	$(HOST_CXX) -Wall -Wextra -O2 -std=c++11 -o $@ server.cpp

clean:
	rm -f client.exe gateway-server

.PHONY: all clean client server

