#include "scanner.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>

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

    char *copy = strdup(spec);
    if (!copy) return -1;

    char *saveptr = NULL;
    char *token = strtok_r(copy, ",", &saveptr);
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
        token = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);

    if (*count == 0) return -1;

    qsort(*ports, *count, sizeof(int), cmp_int);
    return 0;
}

int scanner_resolve_host(scan_config_t *cfg) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = (cfg->protocol == SCAN_PROTO_UDP) ? SOCK_DGRAM : SOCK_STREAM;

    int rc = getaddrinfo(cfg->host, NULL, &hints, &res);
    if (rc != 0 || !res) {
        fprintf(stderr, "erro ao resolver host '%s': %s\n", cfg->host,
                gai_strerror(rc));
        return -1;
    }

    memcpy(&cfg->addr, res->ai_addr, res->ai_addrlen);
    cfg->addr_len = res->ai_addrlen;
    cfg->family = res->ai_family;

    freeaddrinfo(res);
    return 0;
}

static void set_port_in_addr(struct sockaddr_storage *addr, int family, int port) {
    if (family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        sin->sin_port = htons((uint16_t)port);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        sin6->sin6_port = htons((uint16_t)port);
    }
}

/* Service-specific UDP probes. Most UDP services stay silent on an empty
 * datagram, so a handful of well-known probes make results meaningfully
 * more accurate than sending nothing. */
typedef struct {
    int port;
    const unsigned char *payload;
    size_t len;
} udp_probe_t;

static const unsigned char DNS_PROBE[] = {
    0xaa, 0xaa,             /* ID */
    0x01, 0x00,             /* flags: standard query, recursion desired */
    0x00, 0x01,             /* QDCOUNT = 1 */
    0x00, 0x00,             /* ANCOUNT */
    0x00, 0x00,             /* NSCOUNT */
    0x00, 0x00,             /* ARCOUNT */
    0x00,                   /* QNAME: root */
    0x00, 0x01,             /* QTYPE = A */
    0x00, 0x01              /* QCLASS = IN */
};

static const unsigned char NTP_PROBE[48] = { 0x1b };

static const udp_probe_t UDP_PROBES[] = {
    { 53, DNS_PROBE, sizeof(DNS_PROBE) },
    { 123, NTP_PROBE, sizeof(NTP_PROBE) },
};

static void get_udp_probe(int port, const unsigned char **payload, size_t *len) {
    for (size_t i = 0; i < sizeof(UDP_PROBES) / sizeof(UDP_PROBES[0]); i++) {
        if (UDP_PROBES[i].port == port) {
            *payload = UDP_PROBES[i].payload;
            *len = UDP_PROBES[i].len;
            return;
        }
    }
    *payload = NULL;
    *len = 0;
}

static void sanitize_banner(char *out, ssize_t n) {
    out[n] = '\0';
    for (ssize_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)out[i];
        if (c == '\r' || c == '\n') {
            out[i] = ' ';
        } else if (c < 0x20 || c == 0x7f) {
            out[i] = '.';
        }
    }
    /* trim trailing spaces */
    ssize_t end = n - 1;
    while (end >= 0 && out[end] == ' ') {
        out[end] = '\0';
        end--;
    }
}

static const char HTTP_PROBE[] =
    "GET / HTTP/1.0\r\nHost: probe\r\nConnection: close\r\n\r\n";
static const char GENERIC_PROBE[] = "\r\n";

static void get_tcp_probe(int port, const char **payload, size_t *len) {
    switch (port) {
        case 80: case 8080: case 8000: case 8888: case 8081: case 3000:
            *payload = HTTP_PROBE;
            *len = sizeof(HTTP_PROBE) - 1;
            break;
        default:
            *payload = GENERIC_PROBE;
            *len = sizeof(GENERIC_PROBE) - 1;
    }
}

static void grab_banner(int fd, int port, int active, char *out, size_t out_len) {
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int rc = poll(&pfd, 1, active ? 300 : 1000);
    if (rc <= 0) {
        if (!active) {
            out[0] = '\0';
            return;
        }
        const char *probe;
        size_t probe_len;
        get_tcp_probe(port, &probe, &probe_len);
        if (send(fd, probe, probe_len, 0) < 0) {
            out[0] = '\0';
            return;
        }
        rc = poll(&pfd, 1, 700);
        if (rc <= 0) {
            out[0] = '\0';
            return;
        }
    }
    ssize_t n = recv(fd, out, out_len - 1, 0);
    if (n <= 0) {
        out[0] = '\0';
        return;
    }
    sanitize_banner(out, n);
}

static port_status_t scan_single_port_tcp(const scan_config_t *cfg, int port,
                                           int grab_banner_flag, char *banner_out,
                                           size_t banner_len) {
    int fd = socket(cfg->family, SOCK_STREAM, 0);
    if (fd < 0) return PORT_FILTERED;

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_storage addr = cfg->addr;
    set_port_in_addr(&addr, cfg->family, port);

    port_status_t status;
    int rc = connect(fd, (struct sockaddr *)&addr, cfg->addr_len);
    if (rc == 0) {
        status = PORT_OPEN;
    } else if (errno != EINPROGRESS) {
        status = PORT_CLOSED;
    } else {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        int pr = poll(&pfd, 1, cfg->timeout_ms);
        if (pr == 0) {
            status = PORT_FILTERED;
        } else if (pr < 0) {
            status = PORT_FILTERED;
        } else {
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
            status = (so_error == 0) ? PORT_OPEN : PORT_CLOSED;
        }
    }

    if (status == PORT_OPEN && grab_banner_flag) {
        /* switch back to blocking-ish behaviour bounded by poll() timeout */
        int bflags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, bflags & ~O_NONBLOCK);
        grab_banner(fd, port, cfg->active_banner, banner_out, banner_len);
    } else if (banner_out) {
        banner_out[0] = '\0';
    }

    close(fd);
    return status;
}

/* UDP has no handshake, so "open" can only be confirmed by getting a reply.
 * A connected UDP socket surfaces the target's ICMP port-unreachable as
 * ECONNREFUSED on send/recv, which is how we detect PORT_CLOSED; silence
 * within the timeout is the inherent open-vs-filtered ambiguity of UDP
 * scanning. */
static port_status_t scan_single_port_udp(const scan_config_t *cfg, int port,
                                           int grab_banner_flag, char *banner_out,
                                           size_t banner_len) {
    if (banner_out) banner_out[0] = '\0';

    int fd = socket(cfg->family, SOCK_DGRAM, 0);
    if (fd < 0) return PORT_FILTERED;

    struct sockaddr_storage addr = cfg->addr;
    set_port_in_addr(&addr, cfg->family, port);

    if (connect(fd, (struct sockaddr *)&addr, cfg->addr_len) != 0) {
        close(fd);
        return PORT_FILTERED;
    }

    const unsigned char *payload = NULL;
    size_t payload_len = 0;
    get_udp_probe(port, &payload, &payload_len);
    unsigned char empty_probe = 0;
    if (!payload) {
        payload = &empty_probe;
        payload_len = 0;
    }

    port_status_t status;
    ssize_t sn = send(fd, payload, payload_len, 0);
    if (sn < 0 && errno == ECONNREFUSED) {
        close(fd);
        return PORT_CLOSED;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int pr = poll(&pfd, 1, cfg->timeout_ms);
    if (pr <= 0) {
        status = PORT_OPEN_FILTERED;
    } else {
        char buf[256];
        ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
        if (n < 0) {
            status = (errno == ECONNREFUSED) ? PORT_CLOSED : PORT_OPEN_FILTERED;
        } else {
            status = PORT_OPEN;
            if (grab_banner_flag && banner_out && n > 0) {
                size_t copy_len = (size_t)n < banner_len - 1 ? (size_t)n : banner_len - 1;
                memcpy(banner_out, buf, copy_len);
                sanitize_banner(banner_out, (ssize_t)copy_len);
            }
        }
    }

    close(fd);
    return status;
}

static port_status_t scan_single_port(const scan_config_t *cfg, int port,
                                       int grab_banner_flag, char *banner_out,
                                       size_t banner_len) {
    if (cfg->protocol == SCAN_PROTO_UDP) {
        return scan_single_port_udp(cfg, port, grab_banner_flag, banner_out, banner_len);
    }
    return scan_single_port_tcp(cfg, port, grab_banner_flag, banner_out, banner_len);
}

typedef struct {
    scan_config_t *cfg;
    size_t next_index;
    pthread_mutex_t lock;
} work_queue_t;

static void *worker_thread(void *arg) {
    work_queue_t *wq = (work_queue_t *)arg;
    scan_config_t *cfg = wq->cfg;

    for (;;) {
        if (cfg->cancel_flag && *cfg->cancel_flag) break;

        pthread_mutex_lock(&wq->lock);
        size_t idx = wq->next_index;
        if (idx >= cfg->port_count) {
            pthread_mutex_unlock(&wq->lock);
            break;
        }
        wq->next_index++;
        pthread_mutex_unlock(&wq->lock);

        int port = cfg->ports[idx];
        port_result_t *result = &cfg->results[idx];
        result->port = port;
        result->status = scan_single_port(cfg, port, cfg->grab_banner,
                                           result->banner,
                                           sizeof(result->banner));

        if (cfg->on_result) cfg->on_result(result, cfg->on_result_ctx);
    }
    return NULL;
}

void run_scan(scan_config_t *cfg) {
    const char *proto_name = (cfg->protocol == SCAN_PROTO_UDP) ? "udp" : "tcp";
    for (size_t i = 0; i < cfg->port_count; i++) {
        struct servent *se = getservbyport(htons((uint16_t)cfg->ports[i]), proto_name);
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
    pthread_mutex_init(&wq.lock, NULL);

    pthread_t *threads = calloc((size_t)thread_count, sizeof(pthread_t));
    for (int i = 0; i < thread_count; i++) {
        pthread_create(&threads[i], NULL, worker_thread, &wq);
    }
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    pthread_mutex_destroy(&wq.lock);
}

const char *status_to_str(port_status_t status) {
    switch (status) {
        case PORT_OPEN: return "open";
        case PORT_CLOSED: return "closed";
        case PORT_FILTERED: return "filtered";
        case PORT_OPEN_FILTERED: return "open|filtered";
        default: return "?";
    }
}
