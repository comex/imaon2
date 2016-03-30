#include <stdint.h>
struct operand { const char *name; uint32_t val; };
typedef void (*cb_t)(void *, const char *, const struct operand *, uint32_t);
void decode_arm(uint32_t op, cb_t cb, void *ctx) {
    #include "../out-common/debug-dis-arm.c"
}
void decode_thumb(uint32_t op, cb_t cb, void *ctx) {
    #include "../out-common/debug-dis-thumb.c"
}
void decode_thumb2(uint32_t op, cb_t cb, void *ctx) {
    #include "../out-common/debug-dis-thumb2.c"
}
