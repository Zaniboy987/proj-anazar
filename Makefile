CC=g++
CFLAGS=-Wall -w
LIBS=-lssl -lcrypto
SSL_INCLUDE=-I/usr/local/ssl/include/
SSL_LIB=-L/usr/local/ssl/lib

all: server/serv client/cli bank/bank testing/test

server/serv: server/server.cpp
	$(CC) $(CFLAGS) -o $@ $< $(SSL_INCLUDE) $(SSL_LIB) $(LIBS)

client/cli: client/client.cpp
	$(CC) $(CFLAGS) -o $@ $< $(SSL_INCLUDE) $(SSL_LIB) $(LIBS)

bank/bank: bank/bank.cpp
	$(CC) $(CFLAGS) -o $@ $< $(SSL_INCLUDE) $(SSL_LIB) $(LIBS)

testing/test: testing/test.cpp
	$(CC) $(CFLAGS) -o $@ $< $(SSL_INCLUDE) $(SSL_LIB) $(LIBS)

clean:
	rm -f server/serv client/cli bank/bank testing/test
