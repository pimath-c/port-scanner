#ifndef SCANNER_WIN_H
#define SCANNER_WIN_H

#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stddef.h>

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

/* Called from a worker thread right after a port finishes scanning, if set.
 * Implementations must not block and must not touch UI directly from other
 * threads (marshal back to the GUI thread with PostMessage instead). */
typedef void (*port_result_cb)(const port_result_t *result, void *ctx);

typedef struct {
    const char *host;
    struct sockaddr_storage addr;
    int addr_len;
    int family;

    int *ports;
    size_t port_count;

    int timeout_ms;
    int thread_count;
    int grab_banner;

    /* Optional: checked between ports; set *cancel_flag to non-zero to stop. */
    volatile LONG *cancel_flag;

    /* Optional: invoked after each port is scanned. */
    port_result_cb on_result;
    void *on_result_ctx;

    port_result_t *results;
} scan_config_t;

int scanner_winsock_init(void);
void scanner_winsock_cleanup(void);

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
