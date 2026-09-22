#ifndef ADVISORIES_H
#define ADVISORIES_H

/* Looks up the banner text against a small built-in table of known
 * outdated/vulnerable service versions (OpenSSH, Apache, nginx, vsftpd,
 * ProFTPD, ...). This is a static, offline heuristic -- not a live CVE
 * feed -- so it only catches what's in the table and can miss recent
 * advisories or misjudge oddly formatted banners.
 *
 * Returns a static, human-readable advisory string if the banner matches
 * something outdated/known-vulnerable, or NULL if nothing matched. */
const char *advisory_for_banner(const char *banner);

#endif
