#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// SDU må være 4-byte justert. Paddes når vi sender i applikasjonen.
#define MIP_MAX_SDU 2044
#define UPPER_MAX_MSG (2 + MIP_MAX_SDU) // MIP-adresse + TTL + SDU

// Hjelper for padde, slik at SDU er 4-justert.
static inline size_t pad4(size_t n) { return ((n + 3) / 4) * 4; }

// Første melding etter connect(): 1 byte som identifiserer SDU-typen.
int send_registration(int fd, uint8_t sdu_type);

/* Vanlige meldinger: [addr:1][ttl:1][SDU...] */
int send_msg(int fd, uint8_t addr, uint8_t ttl, const void *sdu, size_t len);
ssize_t recv_msg(int fd, uint8_t *src_out, uint8_t *ttl_out, void *sdu_out,
                 size_t cap);
