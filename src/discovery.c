#include "discovery.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

static const int PROBE_PORTS[] = {80, 443, 22, 445, 3389};
#define PROBE_COUNT (sizeof(PROBE_PORTS) / sizeof(PROBE_PORTS[0]))

static void set_port(struct sockaddr_storage *addr, int family, int port) {
    if (family == AF_INET) {
        ((struct sockaddr_in *)addr)->sin_port = htons((uint16_t)port);
    } else {
        ((struct sockaddr_in6 *)addr)->sin6_port = htons((uint16_t)port);
    }
}

int host_is_up(const char *host, int timeout_ms) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;

    struct sockaddr_storage base_addr;
    memcpy(&base_addr, res->ai_addr, res->ai_addrlen);
    socklen_t addr_len = res->ai_addrlen;
    int family = res->ai_family;
    freeaddrinfo(res);

    int fds[PROBE_COUNT];
    for (size_t i = 0; i < PROBE_COUNT; i++) fds[i] = -1;
    int up = 0;

    for (size_t i = 0; i < PROBE_COUNT; i++) {
        int fd = socket(family, SOCK_STREAM, 0);
        if (fd < 0) continue;

        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_storage addr = base_addr;
        set_port(&addr, family, PROBE_PORTS[i]);

        int rc = connect(fd, (struct sockaddr *)&addr, addr_len);
        if (rc == 0 || errno == ECONNREFUSED) {
            /* connected immediately, or the target actively refused: either
             * way something is listening on the network stack. */
            up = 1;
            close(fd);
            break;
        } else if (errno == EINPROGRESS) {
            fds[i] = fd;
        } else {
            close(fd);
        }
    }

    if (!up) {
        struct pollfd pfds[PROBE_COUNT];
        nfds_t nfds = 0;
        for (size_t i = 0; i < PROBE_COUNT; i++) {
            if (fds[i] < 0) continue;
            pfds[nfds].fd = fds[i];
            pfds[nfds].events = POLLOUT;
            nfds++;
        }

        if (nfds > 0 && poll(pfds, nfds, timeout_ms) > 0) {
            for (nfds_t i = 0; i < nfds; i++) {
                if (!pfds[i].revents) continue;
                int so_error = 0;
                socklen_t len = sizeof(so_error);
                getsockopt(pfds[i].fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
                if (so_error == 0 || so_error == ECONNREFUSED) {
                    up = 1;
                    break;
                }
            }
        }
    }

    for (size_t i = 0; i < PROBE_COUNT; i++) {
        if (fds[i] >= 0) close(fds[i]);
    }

    return up;
}
