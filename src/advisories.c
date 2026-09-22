#include "advisories.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int major, minor, patch;
} semver_t;

static int parse_version(const char *s, semver_t *v) {
    v->major = v->minor = v->patch = 0;
    if (!isdigit((unsigned char)*s)) return -1;
    int fields = sscanf(s, "%d.%d.%d", &v->major, &v->minor, &v->patch);
    return fields >= 1 ? 0 : -1;
}

static int semver_lt(semver_t a, semver_t b) {
    if (a.major != b.major) return a.major < b.major;
    if (a.minor != b.minor) return a.minor < b.minor;
    return a.patch < b.patch;
}

typedef struct {
    const char *prefix;   /* substring marking the start of the version */
    semver_t min_safe;
    const char *msg;
} min_version_rule_t;

static const min_version_rule_t MIN_VERSION_RULES[] = {
    { "OpenSSH_", {7, 4, 0},
      "OpenSSH anterior a 7.4: multiplas vulnerabilidades conhecidas, atualize." },
    { "Apache/", {2, 4, 51},
      "Apache httpd anterior a 2.4.51: inclui CVEs de path traversal/RCE corrigidos em versoes posteriores." },
    { "nginx/", {1, 20, 1},
      "nginx anterior a 1.20.1: inclui correcoes de seguranca conhecidas, considere atualizar." },
    { "Microsoft-IIS/", {10, 0, 0},
      "IIS anterior a 10.0 esta fora de suporte estendido em versoes de servidor associadas." },
    { "OpenSSL/", {1, 1, 1},
      "OpenSSL anterior a 1.1.1 esta fora de suporte (sem patches de seguranca)." },
};

typedef struct {
    const char *prefix;
    const char *bad_version;
    const char *msg;
} exact_bad_rule_t;

static const exact_bad_rule_t EXACT_BAD_RULES[] = {
    { "vsftpd ", "2.3.4",
      "vsftpd 2.3.4 contem um backdoor conhecido (CVE-2011-2523)." },
    { "ProFTPD ", "1.3.3c",
      "ProFTPD 1.3.3c contem um backdoor conhecido (CVE-2010-4221)." },
    { "ProFTPD ", "1.3.5",
      "ProFTPD 1.3.5 e anteriores tem vulnerabilidade de leitura/escrita de arquivos (CVE-2015-3306)." },
};

const char *advisory_for_banner(const char *banner) {
    if (!banner || !*banner) return NULL;

    for (size_t i = 0; i < sizeof(EXACT_BAD_RULES) / sizeof(EXACT_BAD_RULES[0]); i++) {
        const exact_bad_rule_t *rule = &EXACT_BAD_RULES[i];
        const char *pos = strstr(banner, rule->prefix);
        if (!pos) continue;
        const char *version_start = pos + strlen(rule->prefix);
        size_t bad_len = strlen(rule->bad_version);
        if (strncmp(version_start, rule->bad_version, bad_len) == 0) {
            return rule->msg;
        }
    }

    for (size_t i = 0; i < sizeof(MIN_VERSION_RULES) / sizeof(MIN_VERSION_RULES[0]); i++) {
        const min_version_rule_t *rule = &MIN_VERSION_RULES[i];
        const char *pos = strstr(banner, rule->prefix);
        if (!pos) continue;
        const char *version_start = pos + strlen(rule->prefix);
        semver_t found;
        if (parse_version(version_start, &found) != 0) continue;
        if (semver_lt(found, rule->min_safe)) {
            return rule->msg;
        }
    }

    return NULL;
}
