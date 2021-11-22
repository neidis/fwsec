#
CFLAGS = -w -g -I/usr/local/ssl/include

all: FastOptAR FastOptBM FastAR FastBM BM AR IR IROpt

FastAR: FastAR.c
	gcc $(CFLAGS) -o $@ $^ -lcrypto

FastOptAR: FastOptAR.c
	gcc $(CFLAGS) -o $@ $^ -lcrypto

FastBM: FastBM.c
	gcc $(CFLAGS) -o $@ $^ -lcrypto

FastOptBM: FastOptBM.c
	gcc $(CFLAGS) -o $@ $^ -lcrypto

BM: BM.c
	gcc $(CFLAGS) -o $@ $^ -lcrypto

AR: AR.c
	gcc $(CFLAGS) -o $@ $^ -lcrypto

IR: IR.c
	gcc $(CFLAGS) -o $@ $^ -lcrypto

IROpt: IROpt.c
	gcc $(CFLAGS) -o $@ $^ -lcrypto -lm

clean: 
	rm FastOptAR FastAR FastBM FastOptBM BM AR IR IROpt
