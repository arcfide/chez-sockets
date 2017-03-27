#ifdef __NT__
#define WIN32
#elif defined __WINDOWS__
#define WIN32
#endif

#ifdef WIN32

#define EXPORTED(type) __declspec ( dllexport ) type cdecl

#include <stddef.h>
#include <winsock2.h>
#include <ws2tcpip.h>

typedef int ssize_t;

#define SCHEME_STATIC

#else

#define EXPORTED(type) type

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <sys/unistd.h>
#include <sys/fcntl.h>

#endif

#ifdef WIN32
extern __declspec(dllimport) int cdecl Sactivate_thread(void);
extern __declspec(dllimport) void cdecl Sdeactivate_thread(void);
#else
#include "scheme.h"
#endif
EXPORTED(int)
get_errno()
{
	return errno;
}
#define GUARD(exp) do { \
    Sdeactivate_thread(); \
    exp; \
    Sactivate_thread(); \
    } while (0)

/* Blocking Accept */
EXPORTED(int)
accept_block(int fd, struct sockaddr *addr, socklen_t *addrlen) {
        int ret;
	GUARD(ret = accept(fd, addr, addrlen));
        return ret;
}

/* Blocking Connect */
EXPORTED(int)
connect_block(int fd, const struct sockaddr *addr, socklen_t addrlen) {
        int ret;
        GUARD(ret = connect(fd, addr, addrlen));
        return ret;
}

/* Blocking Receive */
EXPORTED(ssize_t)
recvfrom_block(int fd, void *buf, size_t len, int flags,
    struct sockaddr *src_addr, socklen_t *addrlen) {
	ssize_t ret;
	GUARD(ret = recvfrom(fd, buf, len, flags, src_addr, addrlen));
        return ret;
}

/* Blocking Send To */
EXPORTED(int)
sendto_block(int fd, const void *buf, size_t len, int flags,
    const struct sockaddr *dest_addr, socklen_t addrlen) {
        ssize_t ret;
        GUARD(ret = sendto(fd, buf, len, flags, dest_addr, addrlen));
        return ret;
}
