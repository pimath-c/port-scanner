#ifndef SCANNER_H
#define SCANNER_H

#include <stddef.h>
#include <netdb.h>

typedef enum {
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED
} port_status_t;

typedef struct {
    int port;
    port_status_t status;
    char service[64];
    char banner[256];
} port_result_t;

typedef struct {
    const char *host;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int family;

    int *ports;
    size_t port_count;

    int timeout_ms;
    int thread_count;
    int grab_banner;

    port_result_t *results;
} scan_config_t;

/* Parses a port spec like "22,80,443,8000-8100" into a sorted, allocated
 * array of ports. Returns 0 on success, -1 on parse error. */
int parse_port_spec(const char *spec, int **ports, size_t *count);

/* Resolves cfg->host into cfg->addr/addr_len/family. Returns 0 on success. */
int scanner_resolve_host(scan_config_t *cfg);

/* Runs the scan described by cfg, filling cfg->results (must already be
 * allocated with cfg->port_count entries). */
void run_scan(scan_config_t *cfg);

const char *status_to_str(port_status_t status);

#endif
