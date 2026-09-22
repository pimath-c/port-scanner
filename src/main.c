#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "advisories.h"
#include "discovery.h"
#include "export.h"
#include "history.h"
#include "scanner.h"
#include "targets.h"

static volatile sig_atomic_t g_scan_interrupted = 0;

static void handle_sigint(int sig) {
    (void)sig;
    g_scan_interrupted = 1;
}

enum { OPT_HISTORY = 1000, OPT_DIFF };

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Uso: %s <host[,host,...]|CIDR> [opcoes]\n"
        "\n"
        "Opcoes:\n"
        "  -p, --ports <spec>     Portas a escanear (ex: 22,80,443 ou 1-1024).\n"
        "                          Padrao: 1-1024\n"
        "  -t, --threads <n>      Numero de threads concorrentes. Padrao: 100\n"
        "  -T, --timeout <ms>     Timeout de conexao em milissegundos. Padrao: 500\n"
        "  -b, --banner           Tenta capturar o banner dos servicos abertos\n"
        "  -B, --active-banner    Banner grab ativo: envia um probe (ex: HTTP GET)\n"
        "                          quando o servico fica em silencio. Implica -b\n"
        "  -a, --all              Mostra todas as portas, nao so as abertas\n"
        "  -u, --udp              Escaneamento UDP (padrao: TCP)\n"
        "  -D, --discover         Descoberta de host antes de escanear (pula hosts\n"
        "                          que nao respondem a nenhum probe TCP comum)\n"
        "  -o, --output <arquivo> Exporta os resultados para um arquivo\n"
        "  -f, --format <fmt>     Formato de exportacao: txt, json ou csv.\n"
        "                          Padrao: txt (ou pela extensao de --output)\n"
        "      --history          Salva o resultado no historico local do host\n"
        "      --diff             Compara com o ultimo scan salvo e mostra as\n"
        "                          mudancas (tambem salva o resultado atual)\n"
        "  -w, --watch <s>        Repete o scan a cada <s> segundos ate Ctrl+C\n"
        "  -h, --help             Mostra esta ajuda\n"
        "\n"
        "Exemplos:\n"
        "  %s scanme.nmap.org -p 1-1000 -t 200 -b\n"
        "  %s 8.8.8.8 -p 53,123 -u\n"
        "  %s 192.168.1.0/24 -D -p 22,80,443 -o rede.json -f json\n"
        "  %s example.com -p 1-1024 -b --diff -w 300\n",
        prog, prog, prog, prog, prog);
}

static double elapsed_seconds(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) +
           (end.tv_nsec - start.tv_nsec) / 1e9;
}

/* Scans one already-resolved host and prints its result table. Returns 0
 * and fills out_results (caller must free it) on success, -1 if the host
 * could not be resolved. */
static int scan_one_host(const char *host, const int *ports, size_t port_count,
                          scan_protocol_t protocol, int timeout_ms, int threads,
                          int grab_banner, int active_banner, int show_all,
                          port_result_t **out_results) {
    scan_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host = host;
    cfg.ports = (int *)ports;
    cfg.port_count = port_count;
    cfg.protocol = protocol;
    cfg.timeout_ms = timeout_ms;
    cfg.thread_count = threads;
    cfg.grab_banner = grab_banner;
    cfg.active_banner = active_banner;
    cfg.cancel_flag = &g_scan_interrupted;

    if (scanner_resolve_host(&cfg) != 0) {
        *out_results = NULL;
        return -1;
    }

    cfg.results = calloc(port_count, sizeof(port_result_t));
    if (!cfg.results) {
        fprintf(stderr, "erro: falha ao alocar memoria\n");
        *out_results = NULL;
        return -1;
    }

    printf("\nEscaneando %s [%s] (%zu porta%s, %d threads, timeout %dms)...\n",
           host, protocol == SCAN_PROTO_UDP ? "UDP" : "TCP", port_count,
           port_count == 1 ? "" : "s", threads, timeout_ms);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    run_scan(&cfg);
    clock_gettime(CLOCK_MONOTONIC, &end);

    if (g_scan_interrupted) {
        printf("Escaneamento interrompido pelo usuario.\n");
    }

    printf("%-8s %-14s %-16s %s\n", "PORTA", "STATUS", "SERVICO", "BANNER");
    printf("%-8s %-14s %-16s %s\n", "-----", "------", "-------", "------");

    int open_count = 0, closed_count = 0, other_count = 0;
    for (size_t i = 0; i < port_count; i++) {
        port_result_t *r = &cfg.results[i];
        if (r->status == PORT_OPEN) open_count++;
        else if (r->status == PORT_CLOSED) closed_count++;
        else other_count++;

        if (!show_all && r->status != PORT_OPEN) continue;

        printf("%-8d %-14s %-16s %s\n", r->port, status_to_str(r->status),
               r->service[0] ? r->service : "-",
               r->banner[0] ? r->banner : "");

        if (r->status == PORT_OPEN && r->banner[0]) {
            const char *advisory = advisory_for_banner(r->banner);
            if (advisory) printf("           ! %s\n", advisory);
        }
    }

    printf("%d aberta(s), %d fechada(s), %d outra(s) em %.2fs\n",
           open_count, closed_count, other_count,
           elapsed_seconds(start, end));

    *out_results = cfg.results;
    return 0;
}

/* One full pass over every target: discovery, scan, advisories, diff,
 * history and export. Returns the number of hosts actually scanned. */
static int run_pass(char **hosts, size_t host_count, const int *ports,
                     size_t port_count, scan_protocol_t protocol, int timeout_ms,
                     int threads, int grab_banner, int active_banner, int show_all,
                     int discover, int want_history, int want_diff,
                     const char *output_path, export_format_t format) {
    host_scan_t *scans = calloc(host_count, sizeof(host_scan_t));
    if (!scans) {
        fprintf(stderr, "erro: falha ao alocar memoria\n");
        return 0;
    }
    size_t scanned = 0;

    for (size_t h = 0; h < host_count && !g_scan_interrupted; h++) {
        const char *host = hosts[h];

        if (discover) {
            int up = host_is_up(host, 400);
            if (up == -1) {
                fprintf(stderr, "\naviso: nao foi possivel resolver '%s', pulando\n", host);
                continue;
            }
            if (up == 0) {
                printf("\n%s parece estar inativo (sem resposta), pulando\n", host);
                continue;
            }
        }

        port_result_t *results = NULL;
        if (scan_one_host(host, ports, port_count, protocol, timeout_ms, threads,
                           grab_banner, active_banner, show_all, &results) != 0) {
            fprintf(stderr, "\nerro: nao foi possivel resolver '%s', pulando\n", host);
            continue;
        }

        host_scan_t *scan = &scans[scanned++];
        scan->host = host;
        scan->protocol = protocol;
        scan->scanned_at = time(NULL);
        scan->results = results;
        scan->count = port_count;

        if (want_diff) {
            history_record_t prev;
            if (history_load_last(host, &prev) == 0) {
                history_diff_print(stdout, host, &prev, scan);
                history_record_free(&prev);
            } else {
                printf("\n(sem historico anterior para %s; este scan sera o primeiro registro)\n", host);
            }
        }
        if (want_history || want_diff) {
            history_append(host, scan);
        }
    }

    if (output_path && scanned > 0) {
        FILE *f = fopen(output_path, "w");
        if (!f) {
            fprintf(stderr, "erro: nao foi possivel abrir '%s' para escrita\n", output_path);
        } else {
            export_write(f, format, scans, scanned);
            fclose(f);
            printf("\nResultados exportados para %s\n", output_path);
        }
    }

    for (size_t i = 0; i < scanned; i++) free(scans[i].results);
    free(scans);
    return (int)scanned;
}

int main(int argc, char **argv) {
    const char *ports_spec = "1-1024";
    int threads = 100;
    int timeout_ms = 500;
    int grab_banner = 0;
    int active_banner = 0;
    int show_all = 0;
    int discover = 0;
    int want_history = 0;
    int want_diff = 0;
    int watch_seconds = 0;
    scan_protocol_t protocol = SCAN_PROTO_TCP;
    const char *output_path = NULL;
    const char *format_name = NULL;

    static struct option long_opts[] = {
        {"ports", required_argument, 0, 'p'},
        {"threads", required_argument, 0, 't'},
        {"timeout", required_argument, 0, 'T'},
        {"banner", no_argument, 0, 'b'},
        {"active-banner", no_argument, 0, 'B'},
        {"all", no_argument, 0, 'a'},
        {"udp", no_argument, 0, 'u'},
        {"discover", no_argument, 0, 'D'},
        {"output", required_argument, 0, 'o'},
        {"format", required_argument, 0, 'f'},
        {"history", no_argument, 0, OPT_HISTORY},
        {"diff", no_argument, 0, OPT_DIFF},
        {"watch", required_argument, 0, 'w'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:t:T:bBauDo:f:w:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'p': ports_spec = optarg; break;
            case 't': threads = atoi(optarg); break;
            case 'T': timeout_ms = atoi(optarg); break;
            case 'b': grab_banner = 1; break;
            case 'B': grab_banner = 1; active_banner = 1; break;
            case 'a': show_all = 1; break;
            case 'u': protocol = SCAN_PROTO_UDP; break;
            case 'D': discover = 1; break;
            case 'o': output_path = optarg; break;
            case 'f': format_name = optarg; break;
            case OPT_HISTORY: want_history = 1; break;
            case OPT_DIFF: want_diff = 1; break;
            case 'w': watch_seconds = atoi(optarg); break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "erro: host nao informado\n\n");
        print_usage(argv[0]);
        return 1;
    }
    const char *targets_spec = argv[optind];

    if (threads < 1) {
        fprintf(stderr, "erro: numero de threads invalido\n");
        return 1;
    }
    if (timeout_ms < 1) {
        fprintf(stderr, "erro: timeout invalido\n");
        return 1;
    }
    if (watch_seconds < 0) {
        fprintf(stderr, "erro: intervalo de watch invalido\n");
        return 1;
    }

    export_format_t format = EXPORT_TXT;
    if (format_name) {
        if (export_format_from_name(format_name, &format) != 0) {
            fprintf(stderr, "erro: formato de exportacao invalido: '%s' (use txt, json ou csv)\n",
                    format_name);
            return 1;
        }
    } else if (output_path) {
        const char *dot = strrchr(output_path, '.');
        if (dot && export_format_from_name(dot + 1, &format) != 0) {
            format = EXPORT_TXT;
        }
    }

    int *ports = NULL;
    size_t port_count = 0;
    if (parse_port_spec(ports_spec, &ports, &port_count) != 0) {
        fprintf(stderr, "erro: especificacao de portas invalida: '%s'\n", ports_spec);
        return 1;
    }

    char **hosts = NULL;
    size_t host_count = 0;
    const char *target_err = NULL;
    if (parse_targets(targets_spec, &hosts, &host_count, 0, &target_err) != 0) {
        fprintf(stderr, "erro: alvo invalido '%s': %s\n", targets_spec, target_err);
        free(ports);
        return 1;
    }

    signal(SIGINT, handle_sigint);

    int total_scanned = 0;
    do {
        total_scanned = run_pass(hosts, host_count, ports, port_count, protocol,
                                  timeout_ms, threads, grab_banner, active_banner,
                                  show_all, discover, want_history, want_diff,
                                  output_path, format);

        if (g_scan_interrupted) break;
        if (watch_seconds <= 0) break;

        printf("\n-- aguardando %ds antes do proximo scan (Ctrl+C para parar) --\n",
               watch_seconds);
        for (int s = 0; s < watch_seconds && !g_scan_interrupted; s++) sleep(1);
    } while (!g_scan_interrupted);

    free_targets(hosts, host_count);
    free(ports);
    return total_scanned > 0 ? 0 : 1;
}
