#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>

#include "wg-obfuscator.h"
#include "pktstats.h"

#define STATS_BLOCK_COUNT       3
#define STATS_VERSION           1

typedef enum {
    STATS_BLK_FREE = 0,
    STATS_BLK_FILLING,
    STATS_BLK_FULL,
    STATS_BLK_WRITING,
} stats_blk_state_t;

typedef struct {
    stats_record_t *recs;
    uint32_t        cap;
    uint32_t        count;
    uint32_t        dropped;
    uint64_t        interval_start_us;
    _Atomic int     state;
} stats_block_t;

static stats_block_t blocks[STATS_BLOCK_COUNT];
static int stats_active = 0;
static int stats_trailer_on = 0;

static char stats_dir[512];
static char stats_prefix[256];
static int stats_interval_sec = 5;
static int stats_max_files = 1000;
static uint32_t stats_block_cap = 1000000;
static int stats_fsync = 0;
static uint64_t stats_run_id_us = 0;
static char stats_section[16];

static int flip_pipe_rd = -1;
static int flip_pipe_wr = -1;
static int handoff_pipe_rd = -1;
static int handoff_pipe_wr = -1;
static pthread_t stats_thread;
static int stats_thread_started = 0;
static volatile sig_atomic_t stats_shutdown_req = 0;

static int stats_cur_idx = 0;
static uint32_t stats_file_index = 0;
static _Atomic uint32_t g_seq_tx = 0;
static uint8_t g_next_stream = 0;

static uint64_t realtime_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

uint64_t stats_now_us(void)
{
    return realtime_us();
}

uint8_t stats_wg_type_flags(const uint8_t *buffer)
{
    (void)buffer;
    return 0;
}

int stats_enabled(void)
{
    return stats_active;
}

int stats_trailer_enabled(void)
{
    return stats_trailer_on;
}

uint32_t stats_seq_next(void)
{
    return atomic_fetch_add_explicit(&g_seq_tx, 1u, memory_order_relaxed);
}

uint8_t stats_alloc_stream(void)
{
    uint8_t id = g_next_stream++;
    return id;
}

static void le32_put(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static uint32_t le32_get(const uint8_t *p)
{
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

int stats_trailer_append(uint8_t *buffer, int *length, uint32_t seq)
{
    int len = *length;
    if (!stats_trailer_on || len < 4 || len + STATS_TRAILER_SIZE > STATS_PACKET_MAX) {
        return -1;
    }
    uint32_t mask = le32_get(buffer + len - 4);
    le32_put(buffer + len, seq ^ mask);
    *length = len + STATS_TRAILER_SIZE;
    return 0;
}

int stats_trailer_strip(uint8_t *buffer, int *length, uint32_t *seq_out)
{
    int len = *length;
    if (!stats_trailer_on || len < 8 || !seq_out) {
        return -1;
    }
    uint32_t mask = le32_get(buffer + len - 8);
    uint32_t wire = le32_get(buffer + len - 4);
    *seq_out = wire ^ mask;
    *length = len - STATS_TRAILER_SIZE;
    return 0;
}

static void write_all_fd(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        p += n;
        len -= (size_t)n;
    }
}

static int mkdir_p(const char *path)
{
    char tmp[512];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(tmp)) {
        return -1;
    }
    memcpy(tmp, path, len + 1);
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }
    for (char *p = tmp + 1; *p; ++p) {
        if (*p != '/') {
            continue;
        }
        *p = 0;
        if (mkdir(tmp, 0750) < 0 && errno != EEXIST) {
            return -1;
        }
        *p = '/';
    }
    if (mkdir(tmp, 0750) < 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static void stats_append_record(uint8_t flags, uint32_t seq, uint64_t t_us, uint16_t len, uint8_t stream, uint8_t wg_type)
{
    stats_block_t *blk = &blocks[stats_cur_idx];
    stats_record_t rec = {
        .t_us = t_us,
        .seq = seq,
        .len = len,
        .stream = stream,
        .flags = (uint8_t)(flags | ((wg_type & 0x03u) << 2)),
    };
    if (blk->count < blk->cap) {
        blk->recs[blk->count++] = rec;
        return;
    }
    blk->dropped++;
}

void stats_record_recv(uint32_t seq, uint64_t t_us, uint16_t len, uint8_t stream, uint8_t wg_type)
{
    if (!stats_active) {
        return;
    }
    stats_append_record(0, seq, t_us, len, stream, wg_type);
}

void stats_record_sent(uint32_t seq, uint64_t t_us, uint16_t len, uint8_t stream, uint8_t wg_type, int error)
{
    if (!stats_active) {
        return;
    }
    uint8_t flags = STATS_FLAG_SENT;
    if (error) {
        flags |= STATS_FLAG_ERROR;
    }
    stats_append_record(flags, seq, t_us, len, stream, wg_type);
}

static int find_free_block(void)
{
    for (int i = 0; i < STATS_BLOCK_COUNT; ++i) {
        if (atomic_load_explicit(&blocks[i].state, memory_order_acquire) == STATS_BLK_FREE) {
            return i;
        }
    }
    return -1;
}

static void write_stats_file(int blk_idx)
{
    stats_block_t *blk = &blocks[blk_idx];
    char path[640];
    char tmp[640];
    snprintf(path, sizeof(path), "%s/%s%03u", stats_dir, stats_prefix, stats_file_index % (uint32_t)stats_max_files);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0) {
        log(LL_WARN, "stats: can't open %s: %s", tmp, strerror(errno));
        return;
    }

    stats_file_hdr_t hdr = {
        .magic = STATS_MAGIC,
        .header_len = STATS_FILE_HDR_SIZE,
        .record_size = STATS_RECORD_SIZE,
        .version = STATS_VERSION,
        .hdr_flags = 0,
        .file_index = stats_file_index % (uint32_t)stats_max_files,
        .run_id_us = stats_run_id_us,
        .interval_start_us = blk->interval_start_us,
        .interval_len_us = (uint32_t)stats_interval_sec * 1000000u,
        .record_count = blk->count,
        .dropped_count = blk->dropped,
        .pid = (uint32_t)getpid(),
    };
    strncpy(hdr.section, stats_section, sizeof(hdr.section) - 1);

    write_all_fd(fd, &hdr, sizeof(hdr));
    if (blk->count) {
        write_all_fd(fd, blk->recs, (size_t)blk->count * sizeof(stats_record_t));
    }
    if (stats_fsync) {
        fsync(fd);
    }
    close(fd);

    if (rename(tmp, path) != 0) {
        log(LL_WARN, "stats: rename %s -> %s failed: %s", tmp, path, strerror(errno));
        unlink(tmp);
        return;
    }

    log(LL_DEBUG, "stats: wrote %s (%u records, %u dropped)", path, blk->count, blk->dropped);
    stats_file_index++;
}

static void flip_active_block(uint64_t boundary_us)
{
    stats_block_t *cur = &blocks[stats_cur_idx];
    atomic_store_explicit(&cur->state, STATS_BLK_FULL, memory_order_release);

    int idx = stats_cur_idx;
    if (write(handoff_pipe_wr, &idx, sizeof(idx)) != (ssize_t)sizeof(idx)) {
        log(LL_WARN, "stats: handoff pipe write failed");
    }

    int next = find_free_block();
    if (next < 0) {
        log(LL_WARN, "stats: no free block at boundary, extending current block");
        return;
    }

    stats_cur_idx = next;
    stats_block_t *nxt = &blocks[stats_cur_idx];
    nxt->count = 0;
    nxt->dropped = 0;
    nxt->interval_start_us = boundary_us;
    atomic_store_explicit(&nxt->state, STATS_BLK_FILLING, memory_order_release);
}

void stats_on_flip_pipe(void)
{
    char buf[64];
    while (read(flip_pipe_rd, buf, sizeof(buf)) > 0) {
    }

    uint64_t now = realtime_us();
    uint64_t interval_us = (uint64_t)stats_interval_sec * 1000000ULL;
    uint64_t boundary = (now / interval_us) * interval_us;
    flip_active_block(boundary);
}

void stats_wake(void)
{
    char c = 1;
    if (flip_pipe_wr >= 0) {
        if (write(flip_pipe_wr, &c, 1) < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            /* nothing useful from signal context */
        }
    }
}

static void *stats_thread_fn(void *arg)
{
    (void)arg;
    uint64_t interval_us = (uint64_t)stats_interval_sec * 1000000ULL;

    while (!stats_shutdown_req) {
        uint64_t now = realtime_us();
        uint64_t next = ((now / interval_us) + 1ULL) * interval_us;
        struct timespec ts = {
            .tv_sec = (time_t)(next / 1000000ULL),
            .tv_nsec = (long)((next % 1000000ULL) * 1000ULL),
        };
        while (clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, &ts) < 0 && errno == EINTR) {
            if (stats_shutdown_req) {
                break;
            }
        }
        if (stats_shutdown_req) {
            break;
        }
        stats_wake();
    }

    return NULL;
}

static void *stats_writer_fn(void *arg)
{
    (void)arg;
    while (1) {
        int blk_idx = -1;
        ssize_t n = read(handoff_pipe_rd, &blk_idx, sizeof(blk_idx));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (stats_shutdown_req) {
                break;
            }
            continue;
        }
        if (n == 0) {
            break;
        }
        if (n != (ssize_t)sizeof(blk_idx) || blk_idx < 0 || blk_idx >= STATS_BLOCK_COUNT) {
            continue;
        }

        stats_block_t *blk = &blocks[blk_idx];
        atomic_store_explicit(&blk->state, STATS_BLK_WRITING, memory_order_release);
        write_stats_file(blk_idx);
        blk->count = 0;
        blk->dropped = 0;
        atomic_store_explicit(&blk->state, STATS_BLK_FREE, memory_order_release);
    }
    return NULL;
}

static pthread_t writer_thread;

int stats_flip_pipe_fd(void)
{
    return flip_pipe_rd;
}

int stats_enable_timestampns(int fd)
{
#ifdef SO_TIMESTAMPNS
    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &on, sizeof(on)) < 0) {
        log(LL_WARN, "stats: SO_TIMESTAMPNS failed: %s", strerror(errno));
        return -1;
    }
    return 0;
#else
    (void)fd;
    return -1;
#endif
}

int stats_init_settings(const stats_settings_t *settings, const char *section)
{
    if (!settings || !settings->stats_dir || !settings->stats_dir[0]) {
        return 0;
    }

    strncpy(stats_dir, settings->stats_dir, sizeof(stats_dir) - 1);
    if (settings->stats_prefix && settings->stats_prefix[0]) {
        strncpy(stats_prefix, settings->stats_prefix, sizeof(stats_prefix) - 1);
    } else if (section && *section) {
        strncpy(stats_prefix, section, sizeof(stats_prefix) - 1);
    } else {
        strncpy(stats_prefix, "stats", sizeof(stats_prefix) - 1);
    }

    stats_interval_sec = settings->stats_interval_sec > 0 ? settings->stats_interval_sec : 5;
    stats_max_files = settings->stats_max_files > 0 ? settings->stats_max_files : 1000;
    stats_block_cap = settings->stats_block_records > 0 ? (uint32_t)settings->stats_block_records : 1000000u;
    stats_fsync = settings->stats_fsync;
    stats_trailer_on = settings->stats_seq_enabled;
    stats_run_id_us = realtime_us();
    strncpy(stats_section, section ? section : "main", sizeof(stats_section) - 1);

    if (mkdir_p(stats_dir) != 0) {
        log(LL_ERROR, "stats: can't create directory %s: %s", stats_dir, strerror(errno));
        return -1;
    }

    for (int i = 0; i < STATS_BLOCK_COUNT; ++i) {
        blocks[i].recs = calloc(stats_block_cap, sizeof(stats_record_t));
        if (!blocks[i].recs) {
            log(LL_ERROR, "stats: out of memory allocating block %d", i);
            return -1;
        }
        blocks[i].cap = stats_block_cap;
        blocks[i].count = 0;
        blocks[i].dropped = 0;
        atomic_store_explicit(&blocks[i].state, STATS_BLK_FREE, memory_order_release);
        for (uint32_t p = 0; p < stats_block_cap; p += 4096 / sizeof(stats_record_t)) {
            blocks[i].recs[p].t_us = 0;
        }
    }

    for (int i = 0; i < STATS_BLOCK_COUNT; ++i) {
        if (mlock(blocks[i].recs, (size_t)stats_block_cap * sizeof(stats_record_t)) != 0) {
            log(LL_DEBUG, "stats: mlock block %d failed: %s", i, strerror(errno));
        }
    }

    int flip[2];
    int handoff[2];
    if (pipe(flip) < 0 || pipe(handoff) < 0) {
        log(LL_ERROR, "stats: pipe() failed: %s", strerror(errno));
        return -1;
    }
    flip_pipe_rd = flip[0];
    flip_pipe_wr = flip[1];
    handoff_pipe_rd = handoff[0];
    handoff_pipe_wr = handoff[1];

    fcntl(flip_pipe_rd, F_SETFL, O_NONBLOCK);
    fcntl(flip_pipe_wr, F_SETFL, O_NONBLOCK);
    fcntl(handoff_pipe_rd, F_SETFL, 0);
    fcntl(handoff_pipe_wr, F_SETFL, O_NONBLOCK);

    stats_cur_idx = 0;
    blocks[0].interval_start_us = realtime_us();
    atomic_store_explicit(&blocks[0].state, STATS_BLK_FILLING, memory_order_release);

    if (pthread_create(&writer_thread, NULL, stats_writer_fn, NULL) != 0) {
        log(LL_ERROR, "stats: can't start writer thread");
        return -1;
    }

    if (pthread_create(&stats_thread, NULL, stats_thread_fn, NULL) != 0) {
        log(LL_ERROR, "stats: can't start boundary thread");
        return -1;
    }
    stats_thread_started = 1;

    stats_active = 1;
    log(LL_INFO, "stats: enabled dir=%s prefix=%s interval=%ds trailer=%s block=%u",
        stats_dir, stats_prefix, stats_interval_sec,
        stats_trailer_on ? "yes" : "no", stats_block_cap);
    return 0;
}

void stats_shutdown(void)
{
    if (!stats_active) {
        return;
    }
    stats_shutdown_req = 1;
    stats_wake();

    if (stats_thread_started) {
        pthread_join(stats_thread, NULL);
    }

    flip_active_block(realtime_us());
    close(handoff_pipe_wr);
    handoff_pipe_wr = -1;
    pthread_join(writer_thread, NULL);

    if (flip_pipe_rd >= 0) {
        close(flip_pipe_rd);
        flip_pipe_rd = -1;
    }
    if (flip_pipe_wr >= 0) {
        close(flip_pipe_wr);
        flip_pipe_wr = -1;
    }
    if (handoff_pipe_rd >= 0) {
        close(handoff_pipe_rd);
        handoff_pipe_rd = -1;
    }

    for (int i = 0; i < STATS_BLOCK_COUNT; ++i) {
        free(blocks[i].recs);
        blocks[i].recs = NULL;
    }
    stats_active = 0;
}
