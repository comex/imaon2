#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
struct rust_str {
    char *bytes;
    size_t length;
};
struct ctx {
    bool is_unidentified;
    bool is_tail;
    bool have_target_addr;
    bool target_addr_is_data; // (not code)
    int8_t kills_reg[3];
    uint64_t base_addr;
    uint64_t target_addr;
};

#ifdef VARIANT_AArch64
// see util.rs
static uint32_t sign_extend(uint32_t self, uint8_t bits) {
    return self | (((uint32_t) 0 - ((self >> (bits - 1)) & 1)) << bits);
}

/*
static void addr_1_BL(struct ctx *ctx, uint32_t addr) {
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
*/
static void R1_out_skipped_Rd_out_8_ADDSWrx(struct ctx *ctx, uint32_t Rd) {
    ctx->kills_reg[0] = Rd;
}
static void Rd_out_177_ADCSWr(struct ctx *ctx, uint32_t Rd) {
    ctx->kills_reg[0] = Rd;
}
static void Rd_out_skipped_dst_out_24_ADDSWrs(struct ctx *ctx, uint32_t dst) {
    ctx->kills_reg[0] = dst;
}
static void Rt2_out_Rt_out_7_LDAXPW(struct ctx *ctx, uint32_t Rt, uint32_t Rt2) {
    ctx->kills_reg[0] = Rt;
    ctx->kills_reg[1] = Rt2;
}
static void Rt_out_206_LDADDALb(struct ctx *ctx, uint32_t Rt) {
    ctx->kills_reg[0] = Rt;
}
static void Rn_Rt2_out_Rt_out_wback_out_skipped_6_LDPSWpost(struct ctx *ctx, uint32_t Rt, uint32_t Rn, uint32_t Rt2) {
    ctx->kills_reg[0] = Rt;
    ctx->kills_reg[1] = Rt2;
    ctx->kills_reg[2] = Rn;
}
static void Rn_Rt_out_wback_out_skipped_18_LDRBBpost(struct ctx *ctx, uint32_t Rt, uint32_t Rn) {
    ctx->kills_reg[0] = Rt;
    ctx->kills_reg[1] = Rn;
}
static void Rn_wback_out_skipped_214_LD1Fourv16b_POST(struct ctx *ctx, uint32_t Rn) {
    ctx->kills_reg[0] = Rn;
}
static void Rt_out_label_3_LDRSWl(struct ctx *ctx, uint32_t Rt, uint32_t label) {
    ctx->kills_reg[0] = Rt;
    ctx->have_target_addr = true;
    ctx->target_addr_is_data = true;
    ctx->target_addr = ctx->base_addr + 4 * sign_extend(label, 19);
}
static void Ws_out_12_STLXPW(struct ctx *ctx, uint32_t Ws) {
    ctx->kills_reg[0] = Ws;
}
static void Xd_out_adrp_skipped_label_1_ADRP(struct ctx *ctx, uint32_t Xd, uint32_t label) {
    ctx->kills_reg[0] = Xd;
    ctx->have_target_addr = true;
    ctx->target_addr_is_data = true;
    ctx->target_addr = ctx->base_addr + 0x1000 * sign_extend(label, 21);
}
static void Xd_out_label_1_ADR(struct ctx *ctx, uint32_t Xd, uint32_t label) {
    ctx->kills_reg[0] = Xd;
    ctx->have_target_addr = true;
    ctx->target_addr_is_data = true;
    ctx->target_addr = ctx->base_addr + sign_extend(label, 21);
}
static void addr_1_BL(struct ctx *ctx, uint32_t addr) {
    ctx->have_target_addr = true;
    ctx->target_addr = ctx->base_addr + 4 * sign_extend(addr, 26);
}
static void addr_branchy_skipped_1_B(struct ctx *ctx, uint32_t addr) {
    ctx->is_tail = true;
    ctx->have_target_addr = true;
    ctx->target_addr = ctx->base_addr + 4 * sign_extend(addr, 26);
}
static void branchy_skipped_4_BR(struct ctx *ctx) {
    ctx->is_tail = true;
}
static void branchy_skipped_target_4_CBNZW(struct ctx *ctx, uint32_t target) {
    ctx->have_target_addr = true;
    ctx->target_addr = ctx->base_addr + 4 * sign_extend(label, 19);
}
static void condbranchy_skipped_4_TBNZW(struct ctx *ctx) {
    ctx->have_target_addr = true;
    ctx->target_addr = ctx->base_addr + 4 * sign_extend(label, 14);
}
static void condbranchy_skipped_target_1_Bcc(struct ctx *ctx, uint32_t target) {
    ctx->have_target_addr = true;
    ctx->target_addr = ctx->base_addr + 4 * sign_extend(label, 19);
}
static void label_3_LDRDl(struct ctx *ctx, uint32_t label) {
    ctx->have_target_addr = true;
    ctx->target_addr_is_data = true;
    ctx->target_addr = ctx->base_addr + 4 * sign_extend(label, 19);
}

static void out_out_skipped_16_CASALb(struct ctx *ctx, uint32_t Rs) {
    ctx->kills_reg[0] = Rs;
}
static void uninteresting_2033_ABSv16i8(struct ctx *ctx) {}
static void unidentified(struct ctx *ctx) {
    ctx->is_unidentified = true;
    ctx->is_tail = true;
}

void FUNC_NAME(struct ctx *ctx, uint32_t op) {
    #include INCLUDE_PATH
}

#endif
