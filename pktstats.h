#ifndef _PKTSTATS_H_
#define _PKTSTATS_H_

#include <stdint.h>

#define STATS_TRAILER_SIZE      4
#define STATS_RECORD_SIZE       16
#define STATS_FILE_HDR_SIZE     64
#define STATS_MAGIC             0x315453424F4757ULL  /* "WGOBST1\0" little-endian */
#define STATS_PACKET_MAX        65535

typedef struct __attribute__((packed)) {
    uint64_t t_us;
    uint32_t seq;
    uint16_t len;
    uint8_t  stream;
    uint8_t  flags;
} stats_record_t;

typedef struct __attribute__((packed)) {
    uint64_t magic;
    uint16_t header_len;
    uint16_t record_size;
    uint16_t version;
    uint16_t hdr_flags;
    uint32_t file_index;
    uint64_t run_id_us;
    uint64_t interval_start_us;
    uint32_t interval_len_us;
    uint32_t record_count;
    uint32_t dropped_count;
    uint32_t pid;
    char     section[12];
} stats_file_hdr_t;

_Static_assert(sizeof(stats_record_t) == STATS_RECORD_SIZE, "stats_record_t size");
_Static_assert(sizeof(stats_file_hdr_t) == STATS_FILE_HDR_SIZE, "stats_file_hdr_t size");

#define STATS_FLAG_SENT   0x01
#define STATS_FLAG_ERROR  0x02

typedef struct {
    const char *stats_dir;
    const char *stats_prefix;       /* NULL → section name or "stats" */
    int stats_interval_sec;         /* 0 → 5 */
    int stats_max_files;            /* 0 → 1000 */
    int stats_block_records;        /* 0 → 1000000 */
    uint8_t stats_seq_enabled;
    uint8_t stats_fsync;
} stats_settings_t;

int stats_enabled(void);
int stats_trailer_enabled(void);

int stats_init_settings(const stats_settings_t *settings, const char *section);
/* wg-obfuscator only; declared in wg-obfuscator.h via obfuscator_config_t */
void stats_shutdown(void);

void stats_wake(void);
void stats_on_flip_pipe(void);

uint32_t stats_seq_next(void);
uint8_t stats_alloc_stream(void);

int stats_trailer_append(uint8_t *buffer, int *length, uint32_t seq);
int stats_trailer_strip(uint8_t *buffer, int *length, uint32_t *seq_out);

void stats_record_recv(uint32_t seq, uint64_t t_us, uint16_t len, uint8_t stream, uint8_t wg_type);
void stats_record_sent(uint32_t seq, uint64_t t_us, uint16_t len, uint8_t stream, uint8_t wg_type, int error);

int stats_flip_pipe_fd(void);

uint64_t stats_now_us(void);
uint8_t stats_wg_type_flags(const uint8_t *buffer);

int stats_enable_timestampns(int fd);

#endif
