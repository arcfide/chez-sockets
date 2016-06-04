SCHEMEH=/usr/local/lib/csv9.4.1/ta6le

.SUFFIXES: .c .so

all: sockets sockets-stub.so socket-ffi-values.so

sockets: sockets.w
	cheztangle sockets.w
	chezweave sockets.w
	pdftex sockets

.c.so:
	gcc -fPIC -shared -I${SCHEMEH} -o $@ $<
	
