#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scanner_win.h"

static volatile LONG g_scan_interrupted = 0;

static void handle_sigint(int sig) {
    (void)sig;
    g_scan_interrupted = 1;
    signal(SIGINT, handle_sigint);
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Uso: %s <host> [opcoes]\n"
        "\n"
        "Opcoes:\n"
        "  -p, --ports <spec>     Portas a escanear (ex: 22,80,443 ou 1-1024).\n"
        "                          Padrao: 1-1024\n"
        "  -t, --threads <n>      Numero de threads concorrentes. Padrao: 100\n"
        "  -T, --timeout <ms>     Timeout de conexao em milissegundos. Padrao: 500\n"
        "  -b, --banner           Tenta capturar o banner dos servicos abertos\n"
        "  -a, --all              Mostra todas as portas, nao so as abertas\n"
        "  -h, --help             Mostra esta ajuda\n"
        "\n"
        "Exemplo:\n"
        "  %s scanme.nmap.org -p 1-1000 -t 200 -b\n",
        prog, prog);
}

int main(int argc, char **argv) {
    const char *ports_spec = "1-1024";
    int threads = 100;
    int timeout_ms = 500;
    int grab_banner = 0;
    int show_all = 0;

    static struct option long_opts[] = {
        {"ports", required_argument, 0, 'p'},
        {"threads", required_argument, 0, 't'},
        {"timeout", required_argument, 0, 'T'},
        {"banner", no_argument, 0, 'b'},
        {"all", no_argument, 0, 'a'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:t:T:bah", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'p': ports_spec = optarg; break;
            case 't': threads = atoi(optarg); break;
            case 'T': timeout_ms = atoi(optarg); break;
            case 'b': grab_banner = 1; break;
            case 'a': show_all = 1; break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "erro: host nao informado\n\n");
        print_usage(argv[0]);
        return 1;
    }
    const char *host = argv[optind];

    if (threads < 1) {
        fprintf(stderr, "erro: numero de threads invalido\n");
        return 1;
    }
    if (timeout_ms < 1) {
        fprintf(stderr, "erro: timeout invalido\n");
        return 1;
    }

    if (scanner_winsock_init() != 0) {
        fprintf(stderr, "erro: falha ao inicializar Winsock\n");
        return 1;
    }

    int *ports = NULL;
    size_t port_count = 0;
    if (parse_port_spec(ports_spec, &ports, &port_count) != 0) {
        fprintf(stderr, "erro: especificacao de portas invalida: '%s'\n", ports_spec);
        scanner_winsock_cleanup();
        return 1;
    }

    scan_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host = host;
    cfg.ports = ports;
    cfg.port_count = port_count;
    cfg.timeout_ms = timeout_ms;
    cfg.thread_count = threads;
    cfg.grab_banner = grab_banner;
    cfg.cancel_flag = &g_scan_interrupted;

    if (scanner_resolve_host(&cfg) != 0) {
        free(ports);
        scanner_winsock_cleanup();
        return 1;
    }

    cfg.results = calloc(port_count, sizeof(port_result_t));
    if (!cfg.results) {
        fprintf(stderr, "erro: falha ao alocar memoria\n");
        free(ports);
        scanner_winsock_cleanup();
        return 1;
    }

    signal(SIGINT, handle_sigint);

    printf("Escaneando %s (%zu porta%s, %d threads, timeout %dms)...\n",
           host, port_count, port_count == 1 ? "" : "s", threads, timeout_ms);

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    run_scan(&cfg);

    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / (double)freq.QuadPart;

    if (g_scan_interrupted) {
        printf("\nEscaneamento interrompido pelo usuario.\n");
    }

    printf("\n%-8s %-10s %-16s %s\n", "PORTA", "STATUS", "SERVICO", "BANNER");
    printf("%-8s %-10s %-16s %s\n", "-----", "------", "-------", "------");

    int open_count = 0, closed_count = 0, filtered_count = 0;
    for (size_t i = 0; i < port_count; i++) {
        port_result_t *r = &cfg.results[i];
        if (r->status == PORT_OPEN) open_count++;
        else if (r->status == PORT_CLOSED) closed_count++;
        else filtered_count++;

        if (!show_all && r->status != PORT_OPEN) continue;

        printf("%-8d %-10s %-16s %s\n", r->port, status_to_str(r->status),
               r->service[0] ? r->service : "-",
               r->banner[0] ? r->banner : "");
    }

    printf("\n%d aberta(s), %d fechada(s), %d filtrada(s) em %.2fs\n",
           open_count, closed_count, filtered_count, elapsed);

    free(cfg.results);
    free(ports);
    scanner_winsock_cleanup();
    return 0;
}
