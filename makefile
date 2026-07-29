CXX = x86_64-w64-mingw32-g++
CXXFLAGS = -Wall -O2 -std=c++11 -static

all: client.exe

client.exe: client.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< -lws2_32

clean:
	rm -f client.exe
