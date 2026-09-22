#include "scanner_win.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp_int(const void *a, const void *b) {
    return (*(const int *)a) - (*(const int *)b);
}

static int append_port(int **ports, size_t *count, size_t *cap, int port) {
    if (port < 1 || port > 65535) return -1;
    if (*count == *cap) {
        size_t new_cap = *cap == 0 ? 64 : *cap * 2;
        int *grown = realloc(*ports, new_cap * sizeof(int));
        if (!grown) return -1;
        *ports = grown;
        *cap = new_cap;
    }
    (*ports)[(*count)++] = port;
    return 0;
}

int parse_port_spec(const char *spec, int **ports, size_t *count) {
    size_t cap = 0;
    *ports = NULL;
    *count = 0;

    char *copy = _strdup(spec);
    if (!copy) return -1;

    char *saveptr = NULL;
    char *token = strtok_s(copy, ",", &saveptr);
    while (token) {
        char *dash = strchr(token, '-');
        if (dash) {
            *dash = '\0';
            char *end_str = dash + 1;
            char *endptr1, *endptr2;
            long start = strtol(token, &endptr1, 10);
            long end = strtol(end_str, &endptr2, 10);
            if (*token == '\0' || *endptr1 != '\0' ||
                *end_str == '\0' || *endptr2 != '\0' ||
                start < 1 || end > 65535 || start > end) {
                free(copy);
                free(*ports);
                *ports = NULL;
                return -1;
            }
            for (long p = start; p <= end; p++) {
                if (append_port(ports, count, &cap, (int)p) != 0) {
                    free(copy);
                    free(*ports);
                    *ports = NULL;
                    return -1;
                }
            }
        } else {
            char *endptr;
            long p = strtol(token, &endptr, 10);
            if (*token == '\0' || *endptr != '\0') {
                free(copy);
                free(*ports);
                *ports = NULL;
                return -1;
            }
            if (append_port(ports, count, &cap, (int)p) != 0) {
                free(copy);
                free(*ports);
                *ports = NULL;
                return -1;
            }
        }
        token = strtok_s(NULL, ",", &saveptr);
    }
    free(copy);

    if (*count == 0) return -1;

    qsort(*ports, *count, sizeof(int), cmp_int);
    return 0;
}

int scanner_winsock_init(void) {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? 0 : -1;
}

void scanner_winsock_cleanup(void) {
    WSACleanup();
}

int scanner_resolve_host(scan_config_t *cfg) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(cfg->host, NULL, &hints, &res);
    if (rc != 0 || !res) {
        fprintf(stderr, "erro ao resolver host '%s'\n", cfg->host);
        return -1;
    }

    memcpy(&cfg->addr, res->ai_addr, res->ai_addrlen);
    cfg->addr_len = (int)res->ai_addrlen;
    cfg->family = res->ai_family;

    freeaddrinfo(res);
    return 0;
}

static void set_port_in_addr(struct sockaddr_storage *addr, int family, int port) {
    if (family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        sin->sin_port = htons((u_short)port);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        sin6->sin6_port = htons((u_short)port);
    }
}

static void grab_banner(SOCKET fd, char *out, size_t out_len) {
    WSAPOLLFD pfd;
    pfd.fd = fd;
    pfd.events = POLLRDNORM;
    pfd.revents = 0;

    int rc = WSAPoll(&pfd, 1, 1000);
    if (rc <= 0) {
        out[0] = '\0';
        return;
    }
    int n = recv(fd, out, (int)(out_len - 1), 0);
    if (n <= 0) {
        out[0] = '\0';
        return;
    }
    out[n] = '\0';
    for (int i = 0; i < n; i++) {
        unsigned char c = (unsigned char)out[i];
        if (c == '\r' || c == '\n') {
            out[i] = ' ';
        } else if (c < 0x20 || c == 0x7f) {
            out[i] = '.';
        }
    }
    int end = n - 1;
    while (end >= 0 && out[end] == ' ') {
        out[end] = '\0';
        end--;
    }
}

static port_status_t scan_single_port(const scan_config_t *cfg, int port,
                                       int grab_banner_flag, char *banner_out,
                                       size_t banner_len) {
    SOCKET fd = socket(cfg->family, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET) return PORT_FILTERED;

    u_long nonblocking = 1;
    ioctlsocket(fd, FIONBIO, &nonblocking);

    struct sockaddr_storage addr = cfg->addr;
    set_port_in_addr(&addr, cfg->family, port);

    port_status_t status;
    int rc = connect(fd, (struct sockaddr *)&addr, cfg->addr_len);
    if (rc == 0) {
        status = PORT_OPEN;
    } else {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            status = PORT_CLOSED;
        } else {
            WSAPOLLFD pfd;
            pfd.fd = fd;
            pfd.events = POLLWRNORM;
            pfd.revents = 0;
            int pr = WSAPoll(&pfd, 1, cfg->timeout_ms);
            if (pr <= 0) {
                status = PORT_FILTERED;
            } else {
                int so_error = 0;
                int len = sizeof(so_error);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&so_error, &len);
                status = (so_error == 0) ? PORT_OPEN : PORT_CLOSED;
            }
        }
    }

    if (status == PORT_OPEN && grab_banner_flag) {
        u_long blocking = 0;
        ioctlsocket(fd, FIONBIO, &blocking);
        grab_banner(fd, banner_out, banner_len);
    } else if (banner_out) {
        banner_out[0] = '\0';
    }

    closesocket(fd);
    return status;
}

typedef struct {
    scan_config_t *cfg;
    size_t next_index;
    CRITICAL_SECTION lock;
} work_queue_t;

static DWORD WINAPI worker_thread(LPVOID arg) {
    work_queue_t *wq = (work_queue_t *)arg;
    scan_config_t *cfg = wq->cfg;

    for (;;) {
        if (cfg->cancel_flag && *cfg->cancel_flag) break;

        EnterCriticalSection(&wq->lock);
        size_t idx = wq->next_index;
        if (idx >= cfg->port_count) {
            LeaveCriticalSection(&wq->lock);
            break;
        }
        wq->next_index++;
        LeaveCriticalSection(&wq->lock);

        int port = cfg->ports[idx];
        port_result_t *result = &cfg->results[idx];
        result->port = port;
        result->status = scan_single_port(cfg, port, cfg->grab_banner,
                                           result->banner,
                                           sizeof(result->banner));

        if (cfg->on_result) cfg->on_result(result, cfg->on_result_ctx);
    }
    return 0;
}

void run_scan(scan_config_t *cfg) {
    for (size_t i = 0; i < cfg->port_count; i++) {
        struct servent *se = getservbyport(htons((u_short)cfg->ports[i]), "tcp");
        if (se && se->s_name) {
            snprintf(cfg->results[i].service, sizeof(cfg->results[i].service),
                     "%s", se->s_name);
        } else {
            cfg->results[i].service[0] = '\0';
        }
        cfg->results[i].banner[0] = '\0';
    }

    int thread_count = cfg->thread_count;
    if ((size_t)thread_count > cfg->port_count) {
        thread_count = (int)cfg->port_count;
    }
    if (thread_count < 1) thread_count = 1;

    work_queue_t wq;
    wq.cfg = cfg;
    wq.next_index = 0;
    InitializeCriticalSection(&wq.lock);

    HANDLE *threads = calloc((size_t)thread_count, sizeof(HANDLE));
    for (int i = 0; i < thread_count; i++) {
        threads[i] = CreateThread(NULL, 0, worker_thread, &wq, 0, NULL);
    }
    /* Waited on individually (rather than WaitForMultipleObjects, which is
     * capped at MAXIMUM_WAIT_OBJECTS = 64) so thread_count can exceed that;
     * the threads themselves still run concurrently regardless of wait order. */
    for (int i = 0; i < thread_count; i++) {
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
    }

    free(threads);
    DeleteCriticalSection(&wq.lock);
}

const char *status_to_str(port_status_t status) {
    switch (status) {
        case PORT_OPEN: return "open";
        case PORT_CLOSED: return "closed";
        case PORT_FILTERED: return "filtered";
        default: return "?";
    }
}
