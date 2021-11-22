#
CFLAGS = -w -g
LDFLAGS: -L/usr/local/include/openssl/lib
CPPFLAGS: -I/usr/local/include/openssl/include

SSL_INSTALL :=/opt/homebrew/Cellar/openssl@3/3.0.0_1
CXX_FLAG = -I${SSL_INSTALL}/include 

all: O_AR

O_AR : AR_original.c
	gcc $(CFLAGS) -o ./build/$@ $^ 
AR: AR.c
	gcc $(CFLAGS) -o ./build/$@ $^ -lcrypto -lssl -lm -g

Fast_AR : Fast_AR.c
	gcc $(CFLAGS) -o ./build/$@ $^ -lcrypto -lssl -lm -g

AR_FAS : AR_FAS.cpp
	g++ $(CFLAGS) -o ./build/$@ $^ -lcrypto -lssl -lm -g

BM_FAS : BM_FAS.cpp
	g++ $(CFLAGS) -o ./build/$@ $^ -lcrypto -lssl -lm -g

AR_FAS_nOpt : AR_FAS_nOpt.cpp
	g++ $(CFLAGS) -o ./build/$@ $^ -lcrypto -lssl -lm -g

clean: 
	rm ./build/AR
