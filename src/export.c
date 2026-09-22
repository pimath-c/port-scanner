#include "export.h"

#include <string.h>
#include <strings.h>

int export_format_from_name(const char *name, export_format_t *out) {
    if (strcasecmp(name, "txt") == 0) { *out = EXPORT_TXT; return 0; }
    if (strcasecmp(name, "json") == 0) { *out = EXPORT_JSON; return 0; }
    if (strcasecmp(name, "csv") == 0) { *out = EXPORT_CSV; return 0; }
    return -1;
}

static void json_escape(FILE *out, const char *s) {
    fputc('"', out);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"': fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            default:
                if (c < 0x20) fprintf(out, "\\u%04x", c);
                else fputc(c, out);
        }
    }
    fputc('"', out);
}

static void csv_field(FILE *out, const char *s) {
    int needs_quotes = strpbrk(s, ",\"\n\r") != NULL;
    if (!needs_quotes) {
        fputs(s, out);
        return;
    }
    fputc('"', out);
    for (; *s; s++) {
        if (*s == '"') fputc('"', out);
        fputc(*s, out);
    }
    fputc('"', out);
}

static void write_json(FILE *out, const host_scan_t *hosts, size_t host_count) {
    fputs("[\n", out);
    for (size_t h = 0; h < host_count; h++) {
        const host_scan_t *hs = &hosts[h];
        fputs("  {\n    \"host\": ", out);
        json_escape(out, hs->host);
        fprintf(out, ",\n    \"protocol\": \"%s\",\n",
                hs->protocol == SCAN_PROTO_UDP ? "udp" : "tcp");
        fprintf(out, "    \"scanned_at\": %ld,\n    \"ports\": [\n", (long)hs->scanned_at);
        for (size_t i = 0; i < hs->count; i++) {
            const port_result_t *r = &hs->results[i];
            fprintf(out, "      { \"port\": %d, \"status\": \"%s\", \"service\": ",
                    r->port, status_to_str(r->status));
            json_escape(out, r->service);
            fputs(", \"banner\": ", out);
            json_escape(out, r->banner);
            fputs(" }", out);
            fputs(i + 1 < hs->count ? ",\n" : "\n", out);
        }
        fputs("    ]\n  }", out);
        fputs(h + 1 < host_count ? ",\n" : "\n", out);
    }
    fputs("]\n", out);
}

static void write_csv(FILE *out, const host_scan_t *hosts, size_t host_count) {
    fputs("host,protocol,port,status,service,banner\n", out);
    for (size_t h = 0; h < host_count; h++) {
        const host_scan_t *hs = &hosts[h];
        const char *proto = hs->protocol == SCAN_PROTO_UDP ? "udp" : "tcp";
        for (size_t i = 0; i < hs->count; i++) {
            const port_result_t *r = &hs->results[i];
            csv_field(out, hs->host);
            fprintf(out, ",%s,%d,%s,", proto, r->port, status_to_str(r->status));
            csv_field(out, r->service);
            fputc(',', out);
            csv_field(out, r->banner);
            fputc('\n', out);
        }
    }
}

static void write_txt(FILE *out, const host_scan_t *hosts, size_t host_count) {
    for (size_t h = 0; h < host_count; h++) {
        const host_scan_t *hs = &hosts[h];
        fprintf(out, "== %s [%s] ==\n", hs->host,
                hs->protocol == SCAN_PROTO_UDP ? "UDP" : "TCP");
        fprintf(out, "%-8s %-14s %-16s %s\n", "PORTA", "STATUS", "SERVICO", "BANNER");
        for (size_t i = 0; i < hs->count; i++) {
            const port_result_t *r = &hs->results[i];
            fprintf(out, "%-8d %-14s %-16s %s\n", r->port, status_to_str(r->status),
                    r->service[0] ? r->service : "-", r->banner);
        }
        fputc('\n', out);
    }
}

void export_write(FILE *out, export_format_t fmt, const host_scan_t *hosts,
                   size_t host_count) {
    switch (fmt) {
        case EXPORT_JSON: write_json(out, hosts, host_count); break;
        case EXPORT_CSV: write_csv(out, hosts, host_count); break;
        case EXPORT_TXT: default: write_txt(out, hosts, host_count); break;
    }
}
