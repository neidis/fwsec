#
CFLAGS = -w -g

all: BM_FAS AR_FAS

BM_FAS: BM_FAS.c
	gcc $(CFLAGS) -o $@ $^ -lcrypto

AR_FAS: AR_FAS.c
	gcc $(CFLAGS) -o $@ $^ -lcrypto

clean: 
	rm BM_FAS AR_FAS
