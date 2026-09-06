#ifndef _UDP_PKTUNNEL_H_
#define _UDP_PKTUNNEL_H_

#include <stdint.h>
#include "wg-obfuscator.h"
#include "uthash.h"

#define UDP_PKTUNNEL_VERSION    "0.1"
#define TUNNEL_POSTBUFFER_SIZE  16
#define TUNNEL_IDLE_MS_DEFAULT  300000
#define TUNNEL_MAX_CLIENTS_DEF  1024
#define TUNNEL_TRAFFIC_LOG_SEC  5

typedef enum {
    TUNNEL_ROLE_CLIENT = 0,
    TUNNEL_ROLE_SERVER = 1,
} tunnel_role_t;

typedef struct {
    int source_lport;
    char target_host[256];
    int target_port;
    char stats_dir[512];
    char stats_prefix[256];
    int stats_interval_sec;
    int stats_max_files;
    int stats_block_records;
    uint8_t stats_seq_enabled;
    uint8_t stats_seq_set;
    uint8_t stats_dir_set;
    uint8_t stats_prefix_set;
    uint8_t stats_fsync;
    int verbose;
    char log_file[512];
    int8_t log_timestamps;
    long idle_timeout_ms;
    int max_clients;
    tunnel_role_t role;
} tunnel_config_t;

typedef struct tunnel_client {
    struct sockaddr_in client_addr;
    int peer_sock;
    long last_activity_ms;
    uint8_t stats_stream;
    uint8_t stats_active;
    UT_hash_handle hh;
} tunnel_client_t;

int tunnel_parse_config(int argc, char **argv, tunnel_config_t *config);
int tunnel_run(const tunnel_config_t *config);

#endif
