#ifndef EXPORT_H
#define EXPORT_H

#include <stdio.h>
#include <time.h>

#include "scanner.h"

typedef enum {
    EXPORT_TXT,
    EXPORT_JSON,
    EXPORT_CSV
} export_format_t;

/* One scanned host's results, as collected by main.c. */
typedef struct {
    const char *host;
    scan_protocol_t protocol;
    time_t scanned_at;
    port_result_t *results;
    size_t count;
} host_scan_t;

/* Parses "txt", "json" or "csv" (case-insensitive). Returns 0 on success. */
int export_format_from_name(const char *name, export_format_t *out);

/* Writes every host's results to `out` in the given format. For CSV/TXT
 * this always writes one row per scanned port; JSON always includes every
 * port too (status included) so the file is a full, unfiltered record. */
void export_write(FILE *out, export_format_t fmt, const host_scan_t *hosts,
                   size_t host_count);

#endif
