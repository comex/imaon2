#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
struct rust_str {
    char *bytes;
    size_t length;
};
struct ctx {
    bool is_tail;
    bool have_target_addr;
    bool target_addr_is_data; // (not code)
    uint64_t base_addr;
    uint64_t target_addr;
};

#ifdef VARIANT_AArch64
// see util.rs
static uint32_t sign_extend(uint32_t self, uint8_t bits) {
    return self | (((uint32_t) 0 - ((self >> (bits - 1)) & 1)) << bits);
}

static void addr_1_BL(struct ctx *ctx, uint32_t addr) {
    ctx->have_target_addr = true;
    ctx->target_addr = ctx->base_addr + sign_extend(addr, 26);
}
static void addr_branchy_1_B(struct ctx *ctx, uint32_t addr) {
    ctx->is_tail = true;
    ctx->have_target_addr = true;
    ctx->target_addr = ctx->base_addr + sign_extend(addr, 26);
}
static void branchy_8_BR(struct ctx *ctx) {
    ctx->is_tail = true;
}
static void condbranchy_5_Bcc(struct ctx *ctx) {
}
static void label_8_ADR(struct ctx *ctx, uint32_t label) {
    ctx->have_target_addr = true;
    ctx->target_addr_is_data = true;
    ctx->target_addr = ctx->base_addr + sign_extend(label, 19);
}
static void uninteresting_2721_ABSv16i8(struct ctx *ctx) {
}
static void unidentified(struct ctx *ctx) {
}


void FUNC_NAME(struct ctx *ctx, uint32_t op) {
    ctx->is_tail = false;
    ctx->have_target_addr = false;
    ctx->target_addr_is_data = false;
    #include INCLUDE_PATH
}

#endif
