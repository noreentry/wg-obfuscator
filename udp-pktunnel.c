/*
 * udp-pktunnel — plain UDP forwarder with pktstats (seq trailer + binary dumps).
 * No WireGuard obfuscation, no STUN. Symmetric NAT-style relay like wg-obfuscator
 * without encode/decode.
 */

#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "udp-pktunnel.h"
#include "pktstats.h"

int verbose = LL_INFO;
char section_name[256] = "main";

static volatile sig_atomic_t shutdown_req = 0;
static tunnel_client_t *clients = NULL;
static int listen_sock = -1;
static struct sockaddr_in forward_addr;
static long idle_timeout_ms = TUNNEL_IDLE_MS_DEFAULT;
static int max_clients = TUNNEL_MAX_CLIENTS_DEF;
static tunnel_role_t tunnel_role = TUNNEL_ROLE_CLIENT;

typedef struct {
    uint64_t rx_pkts;
    uint64_t rx_bytes;
    uint64_t tx_pkts;
    uint64_t tx_bytes;
} traffic_bucket_t;

static traffic_bucket_t traffic_cur;
static time_t traffic_slot = -1;

static void traffic_note_rx(ssize_t nbytes)
{
    if (nbytes <= 0) {
        return;
    }
    traffic_cur.rx_pkts++;
    traffic_cur.rx_bytes += (uint64_t)nbytes;
}

static void traffic_note_tx(ssize_t nbytes)
{
    if (nbytes <= 0) {
        return;
    }
    traffic_cur.tx_pkts++;
    traffic_cur.tx_bytes += (uint64_t)nbytes;
}

static void traffic_log_interval(time_t slot_end)
{
    double sec = (double)TUNNEL_TRAFFIC_LOG_SEC;
    double tx_mbps = (traffic_cur.tx_bytes * 8.0) / (sec * 1000000.0);
    double rx_mbps = (traffic_cur.rx_bytes * 8.0) / (sec * 1000000.0);

    fprintf(stderr,
            "[%ld] tunnel %s: sent %" PRIu64 " pkts %.2f Mbit/s  recv %" PRIu64 " pkts %.2f Mbit/s\n",
            (long)slot_end, section_name,
            traffic_cur.tx_pkts, tx_mbps,
            traffic_cur.rx_pkts, rx_mbps);
    fflush(stderr);

    memset(&traffic_cur, 0, sizeof(traffic_cur));
}

static void traffic_maybe_report(void)
{
    time_t now = time(NULL);
    if (now < 0) {
        return;
    }
    time_t slot = now / TUNNEL_TRAFFIC_LOG_SEC;
    if (traffic_slot < 0) {
        traffic_slot = slot;
        return;
    }
    while (traffic_slot < slot) {
        traffic_slot++;
        traffic_log_interval(traffic_slot * TUNNEL_TRAFFIC_LOG_SEC);
    }
}

const char *version_string(void)
{
#ifdef COMMIT
#ifndef ARCH
    return "udp-pktunnel v" UDP_PKTUNNEL_VERSION " (commit " COMMIT ")";
#else
    return "udp-pktunnel v" UDP_PKTUNNEL_VERSION " (commit " COMMIT ") (" ARCH ")";
#endif
#else
#ifndef ARCH
    return "udp-pktunnel v" UDP_PKTUNNEL_VERSION;
#else
    return "udp-pktunnel v" UDP_PKTUNNEL_VERSION " (" ARCH ")";
#endif
#endif
}

static void on_signal(int sig)
{
    (void)sig;
    shutdown_req = 1;
}

static long now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static ssize_t recv_udp_ts(int fd, uint8_t *buffer, size_t buflen,
                           struct sockaddr_in *addr, socklen_t *addr_len,
                           uint64_t *t_us_out)
{
    *t_us_out = stats_now_us();
#ifdef SO_TIMESTAMPNS
    uint8_t cmsgbuf[CMSG_SPACE(sizeof(struct timespec))];
    struct iovec iov = { .iov_base = buffer, .iov_len = buflen };
    struct msghdr msg = {0};

    msg.msg_name = addr;
    msg.msg_namelen = *addr_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    ssize_t n = recvmsg(fd, &msg, MSG_DONTWAIT);
    if (n < 0) {
        return n;
    }

    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_TIMESTAMPNS) {
            struct timespec *ts = (struct timespec *)CMSG_DATA(c);
            *t_us_out = (uint64_t)ts->tv_sec * 1000000ULL + (uint64_t)ts->tv_nsec / 1000ULL;
            break;
        }
    }
    return n;
#else
    return recvfrom(fd, buffer, buflen, MSG_DONTWAIT, (struct sockaddr *)addr, addr_len);
#endif
}

static ssize_t recv_connected_ts(int fd, uint8_t *buffer, size_t buflen, uint64_t *t_us_out)
{
    *t_us_out = stats_now_us();
#ifdef SO_TIMESTAMPNS
    uint8_t cmsgbuf[CMSG_SPACE(sizeof(struct timespec))];
    struct iovec iov = { .iov_base = buffer, .iov_len = buflen };
    struct msghdr msg = {0};

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    ssize_t n = recvmsg(fd, &msg, MSG_DONTWAIT);
    if (n < 0) {
        return n;
    }

    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_TIMESTAMPNS) {
            struct timespec *ts = (struct timespec *)CMSG_DATA(c);
            *t_us_out = (uint64_t)ts->tv_sec * 1000000ULL + (uint64_t)ts->tv_nsec / 1000ULL;
            break;
        }
    }
    return n;
#else
    return recv(fd, buffer, buflen, MSG_DONTWAIT);
#endif
}

static int resolve_target(const char *host, int port, struct sockaddr_in *out)
{
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_DGRAM,
    };
    struct addrinfo *res = NULL;
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", port);

    int err = getaddrinfo(host, portbuf, &hints, &res);
    if (err != 0 || !res) {
        log(LL_ERROR, "can't resolve target %s:%d: %s", host, port, gai_strerror(err));
        if (res) {
            freeaddrinfo(res);
        }
        return -1;
    }

    memcpy(out, res->ai_addr, sizeof(*out));
    freeaddrinfo(res);
    return 0;
}

static void destroy_client(tunnel_client_t *entry)
{
    if (!entry) {
        return;
    }
    if (entry->peer_sock >= 0) {
        close(entry->peer_sock);
    }
    HASH_DEL(clients, entry);
    free(entry);
}

static void destroy_all_clients(void)
{
    tunnel_client_t *entry, *tmp;
    HASH_ITER(hh, clients, entry, tmp) {
        destroy_client(entry);
    }
}

static tunnel_client_t *find_client(const struct sockaddr_in *addr)
{
    tunnel_client_t *entry = NULL;
    HASH_FIND(hh, clients, addr, sizeof(*addr), entry);
    return entry;
}

static tunnel_client_t *new_client(const struct sockaddr_in *client_addr)
{
    if (HASH_COUNT(clients) >= max_clients) {
        log(LL_WARN, "max clients (%d) reached, dropping %s:%d",
            max_clients, inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
        return NULL;
    }

    tunnel_client_t *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        return NULL;
    }

    memcpy(&entry->client_addr, client_addr, sizeof(entry->client_addr));
    entry->peer_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (entry->peer_sock < 0) {
        free(entry);
        return NULL;
    }

    if (connect(entry->peer_sock, (struct sockaddr *)&forward_addr, sizeof(forward_addr)) < 0) {
        serror("connect peer socket to target");
        close(entry->peer_sock);
        free(entry);
        return NULL;
    }

    stats_enable_timestampns(entry->peer_sock);
    if (set_nonblock(entry->peer_sock) != 0) {
        serror("fcntl O_NONBLOCK peer");
        close(entry->peer_sock);
        free(entry);
        return NULL;
    }
    entry->last_activity_ms = now_ms();
    if (stats_enabled()) {
        entry->stats_stream = stats_alloc_stream();
        log(LL_INFO, "stats stream %u = %s:%d",
            entry->stats_stream,
            inet_ntoa(entry->client_addr.sin_addr),
            ntohs(entry->client_addr.sin_port));
    }

    HASH_ADD(hh, clients, client_addr, sizeof(entry->client_addr), entry);
    log(LL_DEBUG, "new client %s:%d", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
    return entry;
}

static void prune_idle_clients(void)
{
    if (idle_timeout_ms <= 0) {
        return;
    }
    long now = now_ms();
    tunnel_client_t *entry, *tmp;
    HASH_ITER(hh, clients, entry, tmp) {
        if (now - entry->last_activity_ms > idle_timeout_ms) {
            log(LL_INFO, "removing idle client %s:%d",
                inet_ntoa(entry->client_addr.sin_addr), ntohs(entry->client_addr.sin_port));
            destroy_client(entry);
        }
    }
}

static void forward_to_wan(tunnel_client_t *entry, uint8_t *buffer, int length,
                           uint64_t t_recv, int wire_len)
{
    uint32_t seq = 0;
    int send_len = length;
    uint16_t record_len = (uint16_t)wire_len;
    int send_err = 0;

    if (stats_trailer_enabled() && entry->stats_active) {
        seq = stats_seq_next();
        if (stats_trailer_append(buffer, &send_len, seq) != 0) {
            log(LL_DEBUG, "trailer append failed for %s:%d",
                inet_ntoa(entry->client_addr.sin_addr), ntohs(entry->client_addr.sin_port));
            return;
        }
        record_len = (uint16_t)send_len;
    }

    ssize_t sent = sendto(listen_sock, buffer, (size_t)send_len, 0,
                          (struct sockaddr *)&entry->client_addr, sizeof(entry->client_addr));
    if (sent < 0) {
        serror("sendto client");
        send_err = 1;
    } else {
        traffic_note_tx(sent);
    }

    if (stats_trailer_enabled() && entry->stats_active) {
        stats_record_sent(seq, t_recv, record_len, entry->stats_stream, 0, send_err);
    }
    entry->last_activity_ms = now_ms();
}

static void forward_to_peer(tunnel_client_t *entry, uint8_t *buffer, int length,
                            uint64_t t_recv, int wire_len)
{
    uint32_t seq = 0;
    int send_len = length;
    uint16_t record_len = (uint16_t)wire_len;
    int send_err = 0;

    if (stats_trailer_enabled()) {
        seq = stats_seq_next();
        if (stats_trailer_append(buffer, &send_len, seq) != 0) {
            log(LL_DEBUG, "trailer append failed for %s:%d",
                inet_ntoa(entry->client_addr.sin_addr), ntohs(entry->client_addr.sin_port));
            return;
        }
        record_len = (uint16_t)send_len;
    }

    ssize_t sent = send(entry->peer_sock, buffer, (size_t)send_len, 0);
    if (sent < 0) {
        serror("send to target");
        send_err = 1;
    } else {
        traffic_note_tx(sent);
    }

    if (stats_trailer_enabled()) {
        stats_record_sent(seq, t_recv, record_len, entry->stats_stream, 0, send_err);
    }
    entry->last_activity_ms = now_ms();
}

static void handle_client_ingress(tunnel_client_t *entry, uint8_t *buffer, int length,
                                  uint64_t t_recv, int wire_len)
{
    if (tunnel_role == TUNNEL_ROLE_SERVER) {
        forward_to_wan(entry, buffer, length, t_recv, wire_len);
        return;
    }

    uint32_t seq = 0;
    uint16_t record_len = (uint16_t)length;

    if (stats_trailer_enabled()) {
        if (stats_trailer_strip(buffer, &length, &seq) != 0) {
            log(LL_DEBUG, "trailer strip failed from peer for %s:%d",
                inet_ntoa(entry->client_addr.sin_addr), ntohs(entry->client_addr.sin_port));
            return;
        }
        record_len = (uint16_t)wire_len;
        stats_record_recv(seq, t_recv, record_len, entry->stats_stream, 0);
    }

    ssize_t sent = sendto(listen_sock, buffer, (size_t)length, 0,
                          (struct sockaddr *)&entry->client_addr, sizeof(entry->client_addr));
    if (sent < 0) {
        serror("sendto client");
    } else {
        traffic_note_tx(sent);
    }
    entry->last_activity_ms = now_ms();
}

static void handle_listen_ingress(const struct sockaddr_in *client_addr,
                                  uint8_t *buffer, int length, uint64_t t_recv)
{
    tunnel_client_t *entry = find_client(client_addr);
    if (!entry) {
        entry = new_client(client_addr);
        if (!entry) {
            return;
        }
    }

    if (tunnel_role == TUNNEL_ROLE_SERVER) {
        uint32_t seq = 0;
        int payload_len = length;
        uint16_t wire_len = (uint16_t)length;

        if (stats_trailer_enabled()) {
            if (stats_trailer_strip(buffer, &payload_len, &seq) == 0) {
                entry->stats_active = 1;
                stats_record_recv(seq, t_recv, wire_len, entry->stats_stream, 0);
            } else {
                entry->stats_active = 0;
                payload_len = length;
            }
        }

        ssize_t sent = send(entry->peer_sock, buffer, (size_t)payload_len, 0);
        if (sent < 0) {
            serror("send to target");
        } else {
            traffic_note_tx(sent);
        }
        entry->last_activity_ms = now_ms();
        return;
    }

    forward_to_peer(entry, buffer, length, t_recv, length);
}

static int tunnel_listen(const tunnel_config_t *config)
{
    listen_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (listen_sock < 0) {
        serror("socket listen");
        return -1;
    }

    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons((uint16_t)config->source_lport),
    };

    if (bind(listen_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        serror("bind listen");
        close(listen_sock);
        listen_sock = -1;
        return -1;
    }

    stats_enable_timestampns(listen_sock);
    if (set_nonblock(listen_sock) != 0) {
        serror("fcntl O_NONBLOCK listen");
        close(listen_sock);
        listen_sock = -1;
        return -1;
    }
    return 0;
}

int tunnel_run(const tunnel_config_t *config)
{
    if (!config->source_lport || !config->target_host[0] || !config->target_port) {
        log(LL_ERROR, "source-lport and target are required");
        return -1;
    }

    idle_timeout_ms = config->idle_timeout_ms;
    max_clients = config->max_clients;
    tunnel_role = config->role;

    if (resolve_target(config->target_host, config->target_port, &forward_addr) != 0) {
        return -1;
    }

    stats_settings_t stats = {
        .stats_dir = config->stats_dir_set ? config->stats_dir : NULL,
        .stats_prefix = config->stats_prefix_set ? config->stats_prefix : NULL,
        .stats_interval_sec = config->stats_interval_sec,
        .stats_max_files = config->stats_max_files,
        .stats_block_records = config->stats_block_records,
        .stats_seq_enabled = config->stats_seq_enabled,
        .stats_fsync = config->stats_fsync,
    };
    if (stats_init_settings(&stats, section_name) != 0) {
        return -1;
    }

    if (tunnel_listen(config) != 0) {
        stats_shutdown();
        return -1;
    }

    log(LL_INFO, "Listening UDP 0.0.0.0:%d -> %s:%d (plain tunnel, role=%s, trailer=%s)",
        config->source_lport, config->target_host, config->target_port,
        tunnel_role == TUNNEL_ROLE_SERVER ? "server" : "client",
        stats_trailer_enabled() ? "yes" : "no");

    int stats_fd = stats_flip_pipe_fd();
    uint8_t buffer[STATS_PACKET_MAX + TUNNEL_POSTBUFFER_SIZE];
    struct pollfd pfds[2];
    int npoll = 1;
    pfds[0].fd = listen_sock;
    pfds[0].events = POLLIN;
    if (stats_fd >= 0) {
        pfds[1].fd = stats_fd;
        pfds[1].events = POLLIN;
        npoll = 2;
    }

    while (!shutdown_req) {
        int pr = poll(pfds, (nfds_t)npoll, 1000);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            serror("poll");
            break;
        }

        if (pr == 0) {
            prune_idle_clients();
        }

        traffic_maybe_report();

        if (pfds[0].revents & POLLIN) {
            for (;;) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                uint64_t t_recv;
                ssize_t n = recv_udp_ts(listen_sock, buffer, STATS_PACKET_MAX,
                                        &client_addr, &client_len, &t_recv);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    }
                    serror("recvfrom listen");
                    break;
                }
                if (n == 0) {
                    break;
                }
                traffic_note_rx(n);
                handle_listen_ingress(&client_addr, buffer, (int)n, t_recv);
            }
        }

        if (npoll > 1 && (pfds[1].revents & POLLIN)) {
            stats_on_flip_pipe();
        }

        tunnel_client_t *entry, *tmp;
        HASH_ITER(hh, clients, entry, tmp) {
            for (;;) {
                uint64_t t_recv;
                ssize_t n = recv_connected_ts(entry->peer_sock, buffer, STATS_PACKET_MAX, &t_recv);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    }
                    log(LL_DEBUG, "peer recv error for %s:%d",
                        inet_ntoa(entry->client_addr.sin_addr), ntohs(entry->client_addr.sin_port));
                    destroy_client(entry);
                    break;
                }
                if (n == 0) {
                    destroy_client(entry);
                    break;
                }
                traffic_note_rx(n);
                handle_client_ingress(entry, buffer, (int)n, t_recv, (int)n);
            }
        }
    }

    destroy_all_clients();
    if (listen_sock >= 0) {
        close(listen_sock);
        listen_sock = -1;
    }
    stats_shutdown();
    log(LL_INFO, "Stopped.");
    return 0;
}

int main(int argc, char **argv)
{
    tunnel_config_t config;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (tunnel_parse_config(argc, argv, &config) != 0) {
        return EXIT_FAILURE;
    }

    verbose = config.verbose;
    if (config.log_file[0]) {
        log_init(config.log_file, config.log_timestamps);
    }

    log(LL_INFO, "Starting udp-pktunnel %s", UDP_PKTUNNEL_VERSION);
    return tunnel_run(&config) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
