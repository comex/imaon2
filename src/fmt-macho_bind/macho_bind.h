#define type type_ // workaround https://github.com/servo/rust-bindgen/issues/278
#include "mach-o/loader.h"
#include "mach-o/fat.h"
#include "mach-o/nlist.h"
#include "mach-o/reloc.h"
#include "dyld_cache_format.h"
