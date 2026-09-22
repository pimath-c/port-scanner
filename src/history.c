#include "history.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int ensure_history_dir(char *path_out, size_t path_out_len) {
    const char *home = getenv("HOME");
    if (!home || !*home) home = ".";

    char base[512];
    snprintf(base, sizeof(base), "%s/.port-scanner", home);
    mkdir(base, 0700);

    int n = snprintf(path_out, path_out_len, "%s/history", base);
    if (n < 0 || (size_t)n >= path_out_len) return -1;
    mkdir(path_out, 0700);
    return 0;
}

static void sanitize_filename(const char *host, char *out, size_t out_len) {
    size_t j = 0;
    for (size_t i = 0; host[i] && j + 1 < out_len; i++) {
        unsigned char c = (unsigned char)host[i];
        out[j++] = (isalnum(c) || c == '.' || c == '-') ? (char)c : '_';
    }
    out[j] = '\0';
    if (j == 0) snprintf(out, out_len, "_");
}

static int history_file_path(const char *host, char *out, size_t out_len) {
    char dir[512];
    if (ensure_history_dir(dir, sizeof(dir)) != 0) return -1;
    char safe_host[256];
    sanitize_filename(host, safe_host, sizeof(safe_host));
    int n = snprintf(out, out_len, "%s/%s.log", dir, safe_host);
    return (n < 0 || (size_t)n >= out_len) ? -1 : 0;
}

int history_append(const char *host, const host_scan_t *scan) {
    char path[768];
    if (history_file_path(host, path, sizeof(path)) != 0) return -1;

    FILE *f = fopen(path, "a");
    if (!f) return -1;

    fprintf(f, "@ %ld %s %zu\n", (long)scan->scanned_at,
            scan->protocol == SCAN_PROTO_UDP ? "udp" : "tcp", scan->count);
    for (size_t i = 0; i < scan->count; i++) {
        const port_result_t *r = &scan->results[i];
        fprintf(f, "%d %d %s %s\n", r->port, (int)r->status,
                r->service[0] ? r->service : "-",
                r->banner[0] ? r->banner : "-");
    }
    fclose(f);
    return 0;
}

int history_load_last(const char *host, history_record_t *out) {
    char path[768];
    if (history_file_path(host, path, sizeof(path)) != 0) return -1;

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    /* Find the start offset of the last "@ ..." header line. */
    long last_header_offset = -1;
    char line[512];
    long offset = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '@') last_header_offset = offset;
        offset = ftell(f);
    }
    if (last_header_offset < 0) {
        fclose(f);
        return -1;
    }

    fseek(f, last_header_offset, SEEK_SET);
    long ts;
    char proto[8];
    size_t count;
    if (!fgets(line, sizeof(line), f) ||
        sscanf(line, "@ %ld %7s %zu", &ts, proto, &count) != 3) {
        fclose(f);
        return -1;
    }

    out->scanned_at = (time_t)ts;
    out->protocol = strcmp(proto, "udp") == 0 ? SCAN_PROTO_UDP : SCAN_PROTO_TCP;
    out->count = count;
    out->results = count ? calloc(count, sizeof(port_result_t)) : NULL;
    if (count && !out->results) {
        fclose(f);
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        if (!fgets(line, sizeof(line), f)) break;
        int port, status;
        char service[64] = "-";
        int consumed = 0;
        sscanf(line, "%d %d %63s %n", &port, &status, service, &consumed);
        port_result_t *r = &out->results[i];
        r->port = port;
        r->status = (port_status_t)status;
        snprintf(r->service, sizeof(r->service), "%s", strcmp(service, "-") == 0 ? "" : service);

        char *banner = line + consumed;
        size_t blen = strlen(banner);
        while (blen > 0 && (banner[blen - 1] == '\n' || banner[blen - 1] == '\r')) banner[--blen] = '\0';
        snprintf(r->banner, sizeof(r->banner), "%s", strcmp(banner, "-") == 0 ? "" : banner);
    }

    fclose(f);
    return 0;
}

void history_record_free(history_record_t *rec) {
    if (!rec) return;
    free(rec->results);
    rec->results = NULL;
    rec->count = 0;
}

void history_diff_print(FILE *out, const char *host, const history_record_t *prev,
                         const host_scan_t *cur) {
    char time_buf[64];
    struct tm tm_buf;
    localtime_r(&prev->scanned_at, &tm_buf);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    fprintf(out, "\nDiff para %s (comparado com o scan de %s):\n", host, time_buf);

    size_t i = 0, j = 0;
    int changes = 0;
    while (i < prev->count || j < cur->count) {
        int prev_port = (i < prev->count) ? prev->results[i].port : -1;
        int cur_port = (j < cur->count) ? cur->results[j].port : -1;

        if (prev_port != -1 && (cur_port == -1 || prev_port < cur_port)) {
            if (prev->results[i].status == PORT_OPEN) {
                fprintf(out, "  - %d/%s fechou (estava aberta)\n", prev_port,
                        prev->protocol == SCAN_PROTO_UDP ? "udp" : "tcp");
                changes++;
            }
            i++;
        } else if (cur_port != -1 && (prev_port == -1 || cur_port < prev_port)) {
            if (cur->results[j].status == PORT_OPEN) {
                fprintf(out, "  + %d/%s abriu\n", cur_port,
                        cur->protocol == SCAN_PROTO_UDP ? "udp" : "tcp");
                changes++;
            }
            j++;
        } else {
            const port_result_t *pr = &prev->results[i];
            const port_result_t *cr = &cur->results[j];
            if (pr->status != cr->status) {
                fprintf(out, "  ~ %d/%s mudou de %s para %s\n", cur_port,
                        cur->protocol == SCAN_PROTO_UDP ? "udp" : "tcp",
                        status_to_str(pr->status), status_to_str(cr->status));
                changes++;
            } else if (strcmp(pr->banner, cr->banner) != 0 && cr->banner[0]) {
                fprintf(out, "  ~ %d/%s banner mudou: \"%s\" -> \"%s\"\n", cur_port,
                        cur->protocol == SCAN_PROTO_UDP ? "udp" : "tcp", pr->banner, cr->banner);
                changes++;
            }
            i++;
            j++;
        }
    }

    if (!changes) fprintf(out, "  (sem mudancas)\n");
}
