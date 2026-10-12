// reader.h - little-endian, bounds-checked
#include <stdint.h>
#include <stddef.h>

typedef struct { const uint8_t *base; size_t len, pos; int err; } reader_t;

static inline void rd_init(reader_t *r, const uint8_t *b, size_t n) {
  r->base = b; r->len = n; r->pos = 0; r->err = 0;
}
static inline int rd_ok(const reader_t *r, size_t off, size_t n) {
  return off <= r->len && n <= r->len - off;   /* no overflow */
}
static inline uint16_t rd_u16_at(reader_t *r, size_t o) {
  if (!rd_ok(r, o, 2)) { r->err = 1; return 0; }
  return (uint16_t)(r->base[o] | (r->base[o + 1] << 8));
}
static inline uint32_t rd_u32_at(reader_t *r, size_t o) {
  if (!rd_ok(r, o, 4)) { r->err = 1; return 0; }
  return (uint32_t)(r->base[o] | ((uint32_t)r->base[o+1] << 8)
                    | ((uint32_t)r->base[o+2] << 16) | ((uint32_t)r->base[o+3] << 24));
}
static inline uint64_t rd_u64_at(reader_t *r, size_t o) {
  if (!rd_ok(r, o, 8)) { r->err = 1; return 0; }
  return (uint64_t)rd_u32_at(r, o) | ((uint64_t)rd_u32_at(r, o + 4) << 32);
}
static inline uint8_t rd_u8_at(reader_t *r, size_t o) {
  if (!rd_ok(r, o, 1)) { r->err = 1; return 0; }
  return r->base[o];
}
