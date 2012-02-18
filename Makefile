SCHEMEH=/usr/lib/csv8.4/ta6le

.SUFFIXES: .c .so

all: sockets sockets-stub.so socket-ffi-values.so

sockets: sockets.w
	cheztangle sockets.w
	chezweave sockets.w
	xetex -papersize=letter sockets

.c.so:
	gcc -fPIC -shared -I${SCHEMEH} -o $@ $<
	