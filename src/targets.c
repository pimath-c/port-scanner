#include "targets.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_MAX_HOSTS 4096

static int append_host(char ***hosts, size_t *count, size_t *cap, const char *host) {
    if (*count == *cap) {
        size_t new_cap = *cap == 0 ? 16 : *cap * 2;
        char **grown = realloc(*hosts, new_cap * sizeof(char *));
        if (!grown) return -1;
        *hosts = grown;
        *cap = new_cap;
    }
    char *copy = strdup(host);
    if (!copy) return -1;
    (*hosts)[(*count)++] = copy;
    return 0;
}

/* Returns 1 if token looks like "a.b.c.d/n" and fills network/prefix,
 * 0 if it is not a CIDR block at all (caller should treat it as a plain
 * host), -1 if it looks like a CIDR block but is malformed. */
static int try_parse_cidr(const char *token, uint32_t *network_out,
                           unsigned *prefix_out) {
    const char *slash = strchr(token, '/');
    if (!slash) return 0;

    char ip_part[64];
    size_t ip_len = (size_t)(slash - token);
    if (ip_len == 0 || ip_len >= sizeof(ip_part)) return -1;
    memcpy(ip_part, token, ip_len);
    ip_part[ip_len] = '\0';

    struct in_addr ia;
    if (inet_pton(AF_INET, ip_part, &ia) != 1) return -1;

    const char *prefix_str = slash + 1;
    if (*prefix_str == '\0') return -1;
    char *endptr;
    long prefix = strtol(prefix_str, &endptr, 10);
    if (*endptr != '\0' || prefix < 0 || prefix > 32) return -1;

    uint32_t ip_h = ntohl(ia.s_addr);
    uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
    *network_out = ip_h & mask;
    *prefix_out = (unsigned)prefix;
    return 1;
}

static int expand_cidr(uint32_t network, unsigned prefix, char ***hosts,
                        size_t *count, size_t *cap, size_t max_hosts,
                        const char **err) {
    uint64_t host_count = (prefix >= 32) ? 1ULL : (1ULL << (32 - prefix));
    uint64_t usable = (prefix < 31) ? host_count - 2 : host_count;
    if (usable == 0) usable = host_count;

    if (usable > max_hosts) {
        *err = "CIDR range grande demais (use uma faixa menor ou aumente o limite)";
        return -1;
    }

    uint32_t first = (prefix < 31) ? network + 1 : network;
    for (uint64_t i = 0; i < usable; i++) {
        struct in_addr ia;
        ia.s_addr = htonl(first + (uint32_t)i);
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ia, buf, sizeof(buf));
        if (append_host(hosts, count, cap, buf) != 0) {
            *err = "falha ao alocar memoria";
            return -1;
        }
    }
    return 0;
}

int parse_targets(const char *spec, char ***hosts, size_t *count,
                   size_t max_hosts, const char **err) {
    if (max_hosts == 0) max_hosts = DEFAULT_MAX_HOSTS;
    *hosts = NULL;
    *count = 0;
    size_t cap = 0;
    *err = NULL;

    char *copy = strdup(spec);
    if (!copy) {
        *err = "falha ao alocar memoria";
        return -1;
    }

    char *saveptr = NULL;
    char *token = strtok_r(copy, ",", &saveptr);
    while (token) {
        while (isspace((unsigned char)*token)) token++;
        char *end = token + strlen(token);
        while (end > token && isspace((unsigned char)end[-1])) *--end = '\0';

        if (*token == '\0') {
            *err = "endereco vazio na lista de alvos";
            free(copy);
            free_targets(*hosts, *count);
            *hosts = NULL;
            *count = 0;
            return -1;
        }

        uint32_t network;
        unsigned prefix;
        int cidr = try_parse_cidr(token, &network, &prefix);
        if (cidr == 1) {
            if (expand_cidr(network, prefix, hosts, count, &cap, max_hosts, err) != 0) {
                free(copy);
                free_targets(*hosts, *count);
                *hosts = NULL;
                *count = 0;
                return -1;
            }
        } else if (cidr == -1) {
            *err = "bloco CIDR invalido";
            free(copy);
            free_targets(*hosts, *count);
            *hosts = NULL;
            *count = 0;
            return -1;
        } else {
            if (append_host(hosts, count, &cap, token) != 0) {
                *err = "falha ao alocar memoria";
                free(copy);
                free_targets(*hosts, *count);
                *hosts = NULL;
                *count = 0;
                return -1;
            }
        }

        token = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);

    if (*count == 0) {
        *err = "nenhum alvo informado";
        return -1;
    }
    return 0;
}

void free_targets(char **hosts, size_t count) {
    if (!hosts) return;
    for (size_t i = 0; i < count; i++) free(hosts[i]);
    free(hosts);
}
