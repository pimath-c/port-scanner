#ifndef DISCOVERY_H
#define DISCOVERY_H

/* Best-effort, unprivileged host discovery: probes a small set of common
 * TCP ports with a short connect() timeout. The host is considered up if
 * any probe connects, or is actively refused (RST), since both mean
 * something answered on the wire. Silence on every probe is reported as
 * down, which can be a false negative behind a strict firewall -- there is
 * no ICMP echo here since that needs raw-socket privileges.
 *
 * Returns 1 if the host appears up, 0 if it appears down, -1 if the host
 * name could not be resolved at all. */
int host_is_up(const char *host, int timeout_ms);

#endif
