#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
struct rust_str {
    char *bytes;
    size_t length;
};
enum target_addr_type {
    TAT_NONE, TAT_DATA, TAT_CODE,
};
enum insn_type {
    INT_REGULAR, INT_TAIL, INT_UNIDENTIFIED,
    INT_CMP, INT_LDR_SHIFTED, INT_BCC,
}
enum cond {

};
struct ctx {
    // input
    uint64_t base_addr;
    // temp
    uint32_t op;
    // output
    uint8_t insn_type;
    uint8_t target_addr_type;
    bool have_new_val_of_kr0;
    int8_t kills_reg[3];
    uint64_t target_addr;
    uint64_t new_val_of_kr0;
    union {
        struct {
            uint8_t reg;
            uint64_t imm;
        } cmp;
        struct {
            uint8_t base_reg, index_reg;
            uint8_t shift_amount;
        } ldr_shifted;
        struct {
            uint8_t cond;
        } bcc;
    };
};

#ifdef VARIANT_AArch64
// see util.rs
static uint32_t sign_extend(uint32_t self, uint8_t bits) {
    return self | (((uint32_t) 0 - ((self >> (bits - 1)) & 1)) << bits);
}

static void R1_out_skipped_Rd_out_8_ADDSWrx(struct ctx *ctx, uint32_t Rd) {
    ctx->kills_reg[0] = Rd;
}
static void Rd_out_175_ADCSWr(struct ctx *ctx, uint32_t Rd) {
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
    ctx->target_addr_type = TAT_DATA;
    ctx->target_addr = ctx->base_addr + 4 * sign_extend(label, 19);
}
static void Ws_out_12_STLXPW(struct ctx *ctx, uint32_t Ws) {
    ctx->kills_reg[0] = Ws;
}
static void Xd_out_adrp_skipped_label_1_ADRP(struct ctx *ctx, uint32_t Xd, uint32_t label) {
    ctx->kills_reg[0] = Xd;
    ctx->target_addr_type = TAT_DATA;
    ctx->target_addr = ctx->base_addr + 0x1000 * sign_extend(label, 21);
    ctx->have_new_val_of_kr0 = true;
    ctx->new_val_of_kr0 = ctx->target_addr;
}
static void Xd_out_label_1_ADR(struct ctx *ctx, uint32_t Xd, uint32_t label) {
    ctx->kills_reg[0] = Xd;
    ctx->target_addr_type = TAT_DATA;
    ctx->target_addr = ctx->base_addr + sign_extend(label, 21);
    ctx->have_new_val_of_kr0 = true;
    ctx->new_val_of_kr0 = ctx->target_addr;
}
static void addr_1_BL(struct ctx *ctx, uint32_t addr) {
    ctx->target_addr_type = TAT_CODE;
    ctx->target_addr = ctx->base_addr + 4 * sign_extend(addr, 26);
}
static void addr_branchy_skipped_1_B(struct ctx *ctx, uint32_t addr) {
    ctx->insn_type = INT_TAIL;
    ctx->target_addr_type = TAT_CODE;
    ctx->target_addr = ctx->base_addr + 4 * sign_extend(addr, 26);
}
static void branchy_skipped_4_BR(struct ctx *ctx) {
    ctx->insn_type = INT_TAIL;
}
static void branchy_skipped_target_4_CBNZW(struct ctx *ctx, uint32_t target) {
    ctx->target_addr_type = TAT_CODE;
    ctx->target_addr = ctx->base_addr + 4 * sign_extend(label, 19);
}
static void condbranchy_skipped_4_TBNZW(struct ctx *ctx) {
    ctx->target_addr_type = TAT_CODE;
    ctx->target_addr = ctx->base_addr + 4 * sign_extend(label, 14);
}
static void condbranchy_skipped_target_1_Bcc(struct ctx *ctx, uint32_t target) {
    ctx->target_addr_type = TAT_CODE;
    ctx->target_addr = ctx->base_addr + 4 * sign_extend(label, 19);
}
static void label_3_LDRDl(struct ctx *ctx, uint32_t label) {
    ctx->target_addr_type = TAT_DATA;
    ctx->target_addr = ctx->base_addr + 4 * sign_extend(label, 19);
}

static void out_out_skipped_16_CASALb(struct ctx *ctx, uint32_t Rs) {
    ctx->kills_reg[0] = Rs;
}
static void uninteresting_2033_ABSv16i8(struct ctx *ctx) {}
static void unidentified(struct ctx *ctx) {
    ctx->insn_type = INT_UNIDENTIFIED;
}

void Rd_out_skipped_Rn_cmp_skipped_imm_2_SUBSWri(struct ctx *ctx, uint32_t Rn, uint32_t imm) {
    ctx->insn_type = INT_CMP;
}

void Rm_Rn_Rt_out_extend_ldr_shifted_skipped_28_LDRBBroW(struct ctx *ctx, uint32_t Rt, uint32_t Rn, uint32_t extend, uint32_t Rm) {
    ctx->insn_type = INT_LDR_SHIFTED;
    ctx->ldr_shifted.base_reg = Rn;
    ctx->ldr_shifted.index_reg = Rm;
    ctx->ldr_shifted.shift_amount = Rm;

}

void FUNC_NAME(struct ctx *ctx, uint32_t op) {
    ctx->insn_type = INT_REGULAR;
    ctx->kills_reg[0] = ctx->kills_reg[1] = ctx->kills_reg[2] = -1;
    ctx->op = op;
    #include INCLUDE_PATH
}

#endif
