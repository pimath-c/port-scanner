#ifndef HISTORY_H
#define HISTORY_H

#include <stdio.h>

#include "export.h"
#include "scanner.h"

typedef struct {
    time_t scanned_at;
    scan_protocol_t protocol;
    port_result_t *results;
    size_t count;
} history_record_t;

/* Appends `scan` as a new record in this host's history file under
 * ~/.port-scanner/history/. Returns 0 on success. */
int history_append(const char *host, const host_scan_t *scan);

/* Loads the most recent record for `host`, if any. Returns 0 and fills
 * *out (caller must history_record_free it) if a record was found, -1 if
 * there is no history yet or on error. */
int history_load_last(const char *host, history_record_t *out);

void history_record_free(history_record_t *rec);

/* Prints an open/closed/changed diff between `prev` and the current scan
 * to `out`. Both port lists must be sorted by port number ascending (as
 * scan results always are). */
void history_diff_print(FILE *out, const char *host, const history_record_t *prev,
                         const host_scan_t *cur);

#endif
