#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include "udp-pktunnel.h"
#include "mini_argp.h"

static char *arg0;

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    if (!*s) {
        return s;
    }
    char *e = s + strlen(s) - 1;
    while (e > s && isspace((unsigned char)*e)) {
        *e-- = 0;
    }
    return s;
}

static int parse_bool(const char *val)
{
    if (!val) {
        return -1;
    }
    if (!strcasecmp(val, "1") || !strcasecmp(val, "true") || !strcasecmp(val, "yes") || !strcasecmp(val, "on")) {
        return 1;
    }
    if (!strcasecmp(val, "0") || !strcasecmp(val, "false") || !strcasecmp(val, "no") || !strcasecmp(val, "off")) {
        return 0;
    }
    return -1;
}

static void reset_config(tunnel_config_t *config)
{
    memset(config, 0, sizeof(*config));
    config->stats_interval_sec = 5;
    config->stats_max_files = 1000;
    config->stats_block_records = 1000000;
    config->stats_seq_enabled = 1;
    config->verbose = LL_INFO;
    config->log_timestamps = -1;
    config->idle_timeout_ms = TUNNEL_IDLE_MS_DEFAULT;
    config->max_clients = TUNNEL_MAX_CLIENTS_DEF;
    config->role = TUNNEL_ROLE_CLIENT;
}

static int set_kv(tunnel_config_t *config, const char *key, char *val)
{
    val = trim(val);
    if (!strcasecmp(key, "source-lport")) {
        config->source_lport = atoi(val);
        return config->source_lport > 0 && config->source_lport <= 65535 ? 0 : -1;
    }
    if (!strcasecmp(key, "target")) {
        char *colon = strrchr(val, ':');
        if (!colon || colon == val) {
            return -1;
        }
        *colon = 0;
        strncpy(config->target_host, trim(val), sizeof(config->target_host) - 1);
        config->target_port = atoi(colon + 1);
        return config->target_port > 0 && config->target_port <= 65535 ? 0 : -1;
    }
    if (!strcasecmp(key, "stats-dir")) {
        strncpy(config->stats_dir, val, sizeof(config->stats_dir) - 1);
        config->stats_dir_set = 1;
        if (!config->stats_seq_set) {
            config->stats_seq_enabled = 1;
        }
        return 0;
    }
    if (!strcasecmp(key, "stats-prefix")) {
        strncpy(config->stats_prefix, val, sizeof(config->stats_prefix) - 1);
        config->stats_prefix_set = 1;
        return 0;
    }
    if (!strcasecmp(key, "stats-interval")) {
        config->stats_interval_sec = atoi(val);
        return config->stats_interval_sec > 0 && 60 % config->stats_interval_sec == 0 ? 0 : -1;
    }
    if (!strcasecmp(key, "stats-max-files")) {
        config->stats_max_files = atoi(val);
        return config->stats_max_files > 0 ? 0 : -1;
    }
    if (!strcasecmp(key, "stats-block-records")) {
        config->stats_block_records = atoi(val);
        return config->stats_block_records > 0 ? 0 : -1;
    }
    if (!strcasecmp(key, "stats-seq")) {
        int b = parse_bool(val);
        if (b < 0) {
            return -1;
        }
        config->stats_seq_enabled = (uint8_t)b;
        config->stats_seq_set = 1;
        return 0;
    }
    if (!strcasecmp(key, "stats-fsync")) {
        config->stats_fsync = (uint8_t)(parse_bool(val) != 0);
        return 0;
    }
    if (!strcasecmp(key, "verbose")) {
        if (!strcasecmp(val, "ERROR")) {
            config->verbose = LL_ERROR;
        } else if (!strcasecmp(val, "WARN")) {
            config->verbose = LL_WARN;
        } else if (!strcasecmp(val, "INFO")) {
            config->verbose = LL_INFO;
        } else if (!strcasecmp(val, "DEBUG")) {
            config->verbose = LL_DEBUG;
        } else if (!strcasecmp(val, "TRACE")) {
            config->verbose = LL_TRACE;
        } else {
            return -1;
        }
        return 0;
    }
    if (!strcasecmp(key, "log-file")) {
        strncpy(config->log_file, val, sizeof(config->log_file) - 1);
        return 0;
    }
    if (!strcasecmp(key, "log-timestamps")) {
        int b = parse_bool(val);
        if (b < 0) {
            return -1;
        }
        config->log_timestamps = (int8_t)b;
        return 0;
    }
    if (!strcasecmp(key, "idle-timeout")) {
        long sec = atol(val);
        config->idle_timeout_ms = sec > 0 ? sec * 1000L : TUNNEL_IDLE_MS_DEFAULT;
        return 0;
    }
    if (!strcasecmp(key, "max-clients")) {
        config->max_clients = atoi(val);
        return config->max_clients > 0 ? 0 : -1;
    }
    if (!strcasecmp(key, "role")) {
        if (!strcasecmp(val, "client")) {
            config->role = TUNNEL_ROLE_CLIENT;
            return 0;
        }
        if (!strcasecmp(val, "server")) {
            config->role = TUNNEL_ROLE_SERVER;
            return 0;
        }
        return -1;
    }
    return -1;
}

static int load_config_file(const char *path, tunnel_config_t *config)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "%s: can't open config %s\n", arg0, path);
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (!*p || *p == '#' || *p == ';') {
            continue;
        }
        if (*p == '[') {
            continue;
        }
        char *eq = strchr(p, '=');
        if (!eq) {
            continue;
        }
        *eq = 0;
        char *key = trim(p);
        char *val = trim(eq + 1);
        if (set_kv(config, key, val) != 0) {
            fprintf(stderr, "%s: invalid config %s=%s\n", arg0, key, val);
            fclose(f);
            return -1;
        }
    }

    fclose(f);
    return 0;
}

static const mini_argp_opt options[] = {
    { "help", '?', 0 },
    { "config", 'c', 1 },
    { "version", 'V', 0 },
    { NULL, 0, 0 },
};

static int parse_opt(const char *lname, char sname, const char *val, void *data)
{
    tunnel_config_t *config = data;
    switch (sname) {
        case 'c':
            return load_config_file(val, config);
        case '?':
            fprintf(stderr,
                "Usage: %s -c <config>\n"
                "Plain UDP tunnel with optional pktstats seq trailer and binary dumps.\n"
                "No WireGuard obfuscation, no STUN.\n",
                arg0);
            exit(EXIT_SUCCESS);
        case 'V':
            fprintf(stderr, "udp-pktunnel %s\n", UDP_PKTUNNEL_VERSION);
            exit(EXIT_SUCCESS);
        default:
            return -1;
    }
}

int tunnel_parse_config(int argc, char **argv, tunnel_config_t *config)
{
    arg0 = argv[0];
    reset_config(config);
    if (argc == 1) {
        fprintf(stderr, "Usage: %s -c <config>\n", argv[0]);
        return -1;
    }
    return mini_argp_parse(argc, argv, options, config, parse_opt) == 0 ? 0 : -1;
}
