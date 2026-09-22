#ifndef TARGETS_H
#define TARGETS_H

#include <stddef.h>

/* Parses a target spec such as "10.0.0.1", "10.0.0.1,10.0.0.2",
 * "192.168.1.0/24" or a mix of the above, separated by commas.
 * Hostnames are passed through unresolved (one entry each); IPv4 CIDR
 * blocks are expanded into individual host address strings.
 *
 * On success returns 0, *hosts is a heap-allocated array of *count
 * heap-allocated strings (free each string, then the array).
 * On failure returns -1 and sets *err to a static, human-readable reason.
 *
 * max_hosts caps how many addresses a single spec may expand into (a /16
 * or larger would otherwise allocate and scan an unreasonable number of
 * hosts by accident); pass 0 for the default cap. */
int parse_targets(const char *spec, char ***hosts, size_t *count,
                   size_t max_hosts, const char **err);

void free_targets(char **hosts, size_t count);

#endif
