/* Minimal, dependency-free test runner for the port-scanner core modules.
 * Run via `make test`. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "advisories.h"
#include "export.h"
#include "history.h"
#include "scanner.h"
#include "targets.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond) do { \
    g_checks++; \
    if (!(cond)) { \
        g_failures++; \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
    } \
} while (0)

#define RUN(fn) do { fprintf(stderr, "-- %s\n", #fn); fn(); } while (0)

/* ---- parse_port_spec ---- */

static void test_parse_port_spec_list_and_range(void) {
    int *ports; size_t count;
    CHECK(parse_port_spec("22,80,443", &ports, &count) == 0);
    CHECK(count == 3);
    CHECK(ports[0] == 22 && ports[1] == 80 && ports[2] == 443);
    free(ports);

    CHECK(parse_port_spec("8000-8002", &ports, &count) == 0);
    CHECK(count == 3);
    CHECK(ports[0] == 8000 && ports[1] == 8001 && ports[2] == 8002);
    free(ports);
}

static void test_parse_port_spec_sorts_mixed_input(void) {
    int *ports; size_t count;
    CHECK(parse_port_spec("443,22,80", &ports, &count) == 0);
    CHECK(count == 3);
    CHECK(ports[0] == 22 && ports[1] == 80 && ports[2] == 443);
    free(ports);
}

static void test_parse_port_spec_rejects_invalid(void) {
    int *ports; size_t count;
    CHECK(parse_port_spec("abc", &ports, &count) != 0);
    CHECK(parse_port_spec("100-50", &ports, &count) != 0);
    CHECK(parse_port_spec("70000", &ports, &count) != 0);
    CHECK(parse_port_spec("", &ports, &count) != 0);
}

/* ---- parse_targets (multi-host / CIDR) ---- */

static void test_parse_targets_single_and_list(void) {
    char **hosts; size_t count; const char *err;
    CHECK(parse_targets("example.com", &hosts, &count, 0, &err) == 0);
    CHECK(count == 1);
    CHECK(strcmp(hosts[0], "example.com") == 0);
    free_targets(hosts, count);

    CHECK(parse_targets("10.0.0.1,example.com,10.0.0.2", &hosts, &count, 0, &err) == 0);
    CHECK(count == 3);
    CHECK(strcmp(hosts[0], "10.0.0.1") == 0);
    CHECK(strcmp(hosts[1], "example.com") == 0);
    CHECK(strcmp(hosts[2], "10.0.0.2") == 0);
    free_targets(hosts, count);
}

static void test_parse_targets_cidr_excludes_network_and_broadcast(void) {
    char **hosts; size_t count; const char *err;
    CHECK(parse_targets("192.168.1.0/30", &hosts, &count, 0, &err) == 0);
    CHECK(count == 2);
    CHECK(strcmp(hosts[0], "192.168.1.1") == 0);
    CHECK(strcmp(hosts[1], "192.168.1.2") == 0);
    free_targets(hosts, count);
}

static void test_parse_targets_cidr_slash32_is_single_host(void) {
    char **hosts; size_t count; const char *err;
    CHECK(parse_targets("10.1.2.3/32", &hosts, &count, 0, &err) == 0);
    CHECK(count == 1);
    CHECK(strcmp(hosts[0], "10.1.2.3") == 0);
    free_targets(hosts, count);
}

static void test_parse_targets_rejects_oversized_cidr(void) {
    char **hosts; size_t count; const char *err;
    CHECK(parse_targets("10.0.0.0/8", &hosts, &count, 256, &err) != 0);
    CHECK(err != NULL);
}

static void test_parse_targets_rejects_malformed(void) {
    char **hosts; size_t count; const char *err;
    CHECK(parse_targets("10.0.0.1/33", &hosts, &count, 0, &err) != 0);
    CHECK(parse_targets("not-an-ip/24", &hosts, &count, 0, &err) != 0);
}

/* strtok_r-based splitting collapses adjacent commas rather than treating
 * them as empty fields -- lenient on purpose (a stray comma shouldn't
 * blow up an otherwise valid list). */
static void test_parse_targets_collapses_empty_fields(void) {
    char **hosts; size_t count; const char *err;
    CHECK(parse_targets("a,,b", &hosts, &count, 0, &err) == 0);
    CHECK(count == 2);
    CHECK(strcmp(hosts[0], "a") == 0 && strcmp(hosts[1], "b") == 0);
    free_targets(hosts, count);
}

/* ---- status_to_str ---- */

static void test_status_to_str(void) {
    CHECK(strcmp(status_to_str(PORT_OPEN), "open") == 0);
    CHECK(strcmp(status_to_str(PORT_CLOSED), "closed") == 0);
    CHECK(strcmp(status_to_str(PORT_FILTERED), "filtered") == 0);
    CHECK(strcmp(status_to_str(PORT_OPEN_FILTERED), "open|filtered") == 0);
}

/* ---- export ---- */

static void make_result(port_result_t *r, int port, port_status_t status,
                         const char *service, const char *banner) {
    memset(r, 0, sizeof(*r));
    r->port = port;
    r->status = status;
    snprintf(r->service, sizeof(r->service), "%s", service);
    snprintf(r->banner, sizeof(r->banner), "%s", banner);
}

static void test_export_format_from_name(void) {
    export_format_t fmt;
    CHECK(export_format_from_name("json", &fmt) == 0 && fmt == EXPORT_JSON);
    CHECK(export_format_from_name("CSV", &fmt) == 0 && fmt == EXPORT_CSV);
    CHECK(export_format_from_name("txt", &fmt) == 0 && fmt == EXPORT_TXT);
    CHECK(export_format_from_name("xml", &fmt) != 0);
}

static void test_export_csv_escapes_special_chars(void) {
    port_result_t results[1];
    make_result(&results[0], 80, PORT_OPEN, "http", "hello, \"world\"");

    host_scan_t scan = { .host = "10.0.0.1", .protocol = SCAN_PROTO_TCP,
                          .scanned_at = 0, .results = results, .count = 1 };

    char *buf = NULL; size_t buf_len = 0;
    FILE *f = open_memstream(&buf, &buf_len);
    export_write(f, EXPORT_CSV, &scan, 1);
    fclose(f);

    CHECK(strstr(buf, "\"hello, \"\"world\"\"\"") != NULL);
    free(buf);
}

static void test_export_json_escapes_and_structure(void) {
    port_result_t results[1];
    make_result(&results[0], 22, PORT_OPEN, "ssh", "OpenSSH_7.4 \\ \"test\"");

    host_scan_t scan = { .host = "example.com", .protocol = SCAN_PROTO_TCP,
                          .scanned_at = 0, .results = results, .count = 1 };

    char *buf = NULL; size_t buf_len = 0;
    FILE *f = open_memstream(&buf, &buf_len);
    export_write(f, EXPORT_JSON, &scan, 1);
    fclose(f);

    CHECK(strstr(buf, "\"host\": \"example.com\"") != NULL);
    CHECK(strstr(buf, "\\\\ \\\"test\\\"") != NULL);
    free(buf);
}

/* ---- advisories ---- */

static void test_advisories_known_backdoor(void) {
    CHECK(advisory_for_banner("220 (vsftpd 2.3.4)") != NULL);
    CHECK(advisory_for_banner("220 (vsftpd 3.0.5)") == NULL);
}

static void test_advisories_outdated_min_version(void) {
    CHECK(advisory_for_banner("SSH-2.0-OpenSSH_6.6") != NULL);
    CHECK(advisory_for_banner("SSH-2.0-OpenSSH_9.3") == NULL);
}

static void test_advisories_no_match(void) {
    CHECK(advisory_for_banner("") == NULL);
    CHECK(advisory_for_banner("some random banner text") == NULL);
}

/* ---- history / diff ---- */

static void test_history_roundtrip_and_diff(void) {
    char home_template[] = "/tmp/port-scanner-test-home-XXXXXX";
    char *home = mkdtemp(home_template);
    CHECK(home != NULL);
    setenv("HOME", home, 1);

    port_result_t prev_results[2];
    make_result(&prev_results[0], 22, PORT_CLOSED, "ssh", "");
    make_result(&prev_results[1], 80, PORT_OPEN, "http", "nginx/1.0.0");
    host_scan_t prev_scan = { .host = "test.local", .protocol = SCAN_PROTO_TCP,
                               .scanned_at = time(NULL) - 60,
                               .results = prev_results, .count = 2 };
    CHECK(history_append("test.local", &prev_scan) == 0);

    history_record_t loaded;
    CHECK(history_load_last("test.local", &loaded) == 0);
    CHECK(loaded.count == 2);
    CHECK(loaded.results[0].port == 22 && loaded.results[0].status == PORT_CLOSED);
    CHECK(loaded.results[1].port == 80 && loaded.results[1].status == PORT_OPEN);
    CHECK(strcmp(loaded.results[1].banner, "nginx/1.0.0") == 0);

    port_result_t cur_results[2];
    make_result(&cur_results[0], 22, PORT_OPEN, "ssh", "");
    make_result(&cur_results[1], 80, PORT_CLOSED, "http", "");
    host_scan_t cur_scan = { .host = "test.local", .protocol = SCAN_PROTO_TCP,
                              .scanned_at = time(NULL),
                              .results = cur_results, .count = 2 };

    char *buf = NULL; size_t buf_len = 0;
    FILE *f = open_memstream(&buf, &buf_len);
    history_diff_print(f, "test.local", &loaded, &cur_scan);
    fclose(f);

    CHECK(strstr(buf, "22/tcp mudou de closed para open") != NULL);
    CHECK(strstr(buf, "80/tcp mudou de open para closed") != NULL);

    free(buf);
    history_record_free(&loaded);
}

int main(void) {
    RUN(test_parse_port_spec_list_and_range);
    RUN(test_parse_port_spec_sorts_mixed_input);
    RUN(test_parse_port_spec_rejects_invalid);
    RUN(test_parse_targets_single_and_list);
    RUN(test_parse_targets_cidr_excludes_network_and_broadcast);
    RUN(test_parse_targets_cidr_slash32_is_single_host);
    RUN(test_parse_targets_rejects_oversized_cidr);
    RUN(test_parse_targets_rejects_malformed);
    RUN(test_parse_targets_collapses_empty_fields);
    RUN(test_status_to_str);
    RUN(test_export_format_from_name);
    RUN(test_export_csv_escapes_special_chars);
    RUN(test_export_json_escapes_and_structure);
    RUN(test_advisories_known_backdoor);
    RUN(test_advisories_outdated_min_version);
    RUN(test_advisories_no_match);
    RUN(test_history_roundtrip_and_diff);

    fprintf(stderr, "\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
