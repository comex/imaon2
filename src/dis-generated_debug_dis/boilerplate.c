#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
struct rust_str {
    char *bytes;
    size_t length;
};
struct operand {
    struct rust_str name;
    uint32_t val;
};
#define MAX_OPS 8

#define RUST_STR_LIT(lit) \
    ((struct rust_str) { (lit), sizeof(lit) - 1 })

#define PUSH_OPERAND(_name, _val) do { \
    ops->name = RUST_STR_LIT(_name); \
    ops->val = (_val); \
    ops++; \
} while (0)

#define RETURN_INSN(name) do { \
    *namep = RUST_STR_LIT(name); \
    return; \
} while (0)

void FUNC_NAME(uint32_t op, struct rust_str *namep, struct operand ops[static MAX_OPS]) {
    #include INCLUDE_PATH
}
