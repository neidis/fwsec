CINCLUDE = -I /usr/local/include/pbc -L /usr/local/lib -Wl,-rpath /usr/local/lib 
LIBS = -lpbc -lgmp -lcrypto
CFLAGS = -w -g $(CINCLUDE)

#hibe: hibe.c
#	gcc $(CFLAGS) -o $@ $^ $(LIBS)

#hibe2: hibe2.c
#	gcc $(CFLAGS) -o $@ $^ $(LIBS)

fsibs: fsibs.c
	gcc $(CFLAGS) -o $@ $^ $(LIBS)

clean: 
	rm fsibs 
