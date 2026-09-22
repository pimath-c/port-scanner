#ifndef SCANNER_H
#define SCANNER_H

#include <signal.h>
#include <stddef.h>
#include <netdb.h>

typedef enum {
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED,
    /* UDP only: no response and no ICMP unreachable came back, so we
     * genuinely cannot tell open from filtered (same convention nmap uses
     * for UDP scans). */
    PORT_OPEN_FILTERED
} port_status_t;

typedef enum {
    SCAN_PROTO_TCP = 0,
    SCAN_PROTO_UDP
} scan_protocol_t;

typedef struct {
    int port;
    port_status_t status;
    char service[64];
    char banner[256];
} port_result_t;

/* Called from a worker thread right after a port finishes scanning, if set.
 * Implementations must not block and must not touch cfg/results directly
 * from other threads (e.g. a GUI must marshal the update back to its main
 * thread instead of touching widgets here). */
typedef void (*port_result_cb)(const port_result_t *result, void *ctx);

typedef struct {
    const char *host;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int family;

    int *ports;
    size_t port_count;

    /* Defaults to SCAN_PROTO_TCP (0) when the struct is zero-initialized. */
    scan_protocol_t protocol;

    int timeout_ms;
    int thread_count;
    int grab_banner;

    /* Optional: checked between ports; set *cancel_flag to stop early. */
    volatile sig_atomic_t *cancel_flag;

    /* Optional: invoked after each port is scanned. */
    port_result_cb on_result;
    void *on_result_ctx;

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
