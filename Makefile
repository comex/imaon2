# This Makefile is public domain.

RUSTC := rustc
TARGET :=

ifneq ($(USE_LLVM),)
    ifeq ($(USE_LLVM),1)
        NODE := node --harmony --use_strict
        LLVM := /usr/src/rust/src/llvm
    else ifeq ($(USE_LLVM),0)
        override USE_LLVM=
    else
        $(error USE_LLVM should be blank, 0, or 1)
    endif
	override RUSTFLAGS := $(RUSTFLAGS) --cfg 'feature = "use_llvm"'
	override CARGO_BUILD_FLAGS := $(CARGO_BUILD_FLAGS) --features use_llvm
endif

override RUSTFLAGS := $(RUSTFLAGS) -Z no-landing-pads
ifeq ($(OPT),1)
LIB := rlib
override RUSTFLAGS := $(RUSTFLAGS) -O --cfg opt
#RUSTFLAGS_bin := -C lto
CARGO_BUILD_TYPE := release
override CARGO_BUILD_FLAGS := $(CARGO_BUILD_FLAGS) --release
OUT := ./outopt
NOT_OUT := ./out
else
ifneq ($(OPT),0)
    ifneq ($(OPT),)
        $(error OPT should be blank, 0, or 1)
    endif
endif
LIB := dylib
override RUSTFLAGS := $(RUSTFLAGS) -C codegen-units=1 -C prefer-dynamic
ifneq ($(NDEBUG),1)
override RUSTFLAGS := $(RUSTFLAGS) -g
endif
CARGO_BUILD_TYPE := debug
#CARGO_BUILD_FLAGS :=
OUT := ./out
NOT_OUT := ./outopt
endif

ifneq ($(TARGET),)
TARGET_DIR := $(CURDIR)/target/x86*# xxx
override CARGO_BUILD_FLAGS := $(CARGO_BUILD_FLAGS) --target $(TARGET)
override RUSTFLAGS := $(RUSTFLAGS) --target $(TARGET)
else
TARGET_DIR := $(CURDIR)/target
endif

OUT_COMMON := ./out-common
$(shell mkdir -p $(OUT) $(OUT_COMMON))
cratefile_dylib = $(OUT)/lib$(1).dylib
cratefile_rlib = $(OUT)/lib$(1).rlib
cratefile_bin = $(OUT)/$(1)

rustc-extern = --extern $(1)=`ls -t $(TARGET_DIR)/$(CARGO_BUILD_TYPE)/deps/lib$(1)*.*lib | head -n 1`
XRUSTC := $(RUSTC) $(RUSTFLAGS) -L$(OUT)
RUSTFLAGS_DEPS := -L $(TARGET_DIR)/$(CARGO_BUILD_TYPE)/deps -L dependency=$(TARGET_DIR)/$(CARGO_BUILD_TYPE)/deps $(if $(USE_LLVM),$(call rustc-extern,autollvm),) $(call rustc-extern,vec_map) $(call rustc-extern,nodrop) $(call rustc-extern,fnv)


all:

define define_crate_
# 1=kind 2=name 3=sources 4=deps 5=file-deps
cratefile-$(2) := $$(call cratefile_$(1),$(2))

depflags-$(2) := $(if $(filter deps,$(2) $(4)),$(RUSTFLAGS_DEPS),)

# specify -o explicitly?
$$(cratefile-$(2)): $(3) Makefile $$(foreach dep,$(4),$$(cratefile-$$(dep))) $(5)
	$(XRUSTC) $(RUSTFLAGS_$(1)) $$(depflags-$(2)) \
	--crate-type $(1) --out-dir $(OUT) $$<

all: $$(cratefile-$(2))

out/test-$(2): $(3) Makefile $$(foreach dep,$(4),$$(if $$(cratefile-$$(dep)),\
													   $$(cratefile-$$(dep)),\
													   $$(error undeclared dep $$(dep))))
	$(XRUSTC) $$(depflags-$(2)) -g --crate-type dylib --test -o $$@ $$<

# separate rule to avoid deleting it on failure
do-test-$(2): out/test-$(2)
	./$$<

test: do-test-$(2)
endef
define_crate = $(eval $(define_crate_))

$(call define_crate,rlib,macros,macros.rs,)
$(call define_crate,$(LIB),bsdlike_getopts,forks/bsdlike_getopts.rs,)

$(call define_crate,$(LIB),deps,deps.rs)
$(cratefile-deps): $(OUT)/cargo-build

$(call define_crate,$(LIB),util,util.rs trivial_hasher.rs forks/small_vector.rs,macros bsdlike_getopts deps)

ifneq ($(USE_LLVM),)
# deps here are wonky
tables/llvm-tblgen: tables/build-tblgen.sh $(LLVM)
	cd tables; ./build-tblgen.sh "$(LLVM)"

LLVM_TARGETS := X86/X86 ARM/ARM Sparc/Sparc Mips/Mips AArch64/AArch64 PowerPC/PPC
define td_target_
$(OUT_COMMON)/out-$(1).td: $(LLVM)/lib/Target/$(1) $(LLVM) tables/llvm-tblgen
	tables/llvm-tblgen -I$(LLVM)/include -I$$< $$</$(2).td -o $$@
$(OUT_COMMON)/out-$(1).json: $(OUT_COMMON)/out-$(1).td tables/untable.js tables/untable.peg
	$(NODE) tables/untable.js $$< $$@
out-td: $(OUT_COMMON)/out-$(1).td $(OUT_COMMON)/out-$(1).json

endef
td_target = $(call td_target_,$(word 1,$(1)),$(word 2,$(1)))
$(foreach target,$(LLVM_TARGETS),$(eval $(call td_target,$(subst /, ,$(target)))))
all: out-td


GEN_JUMP_DIS := $(NODE) tables/gen.js --gen-jump-disassembler --out-lang=rust
GEN_DEBUG_DIS := $(NODE) tables/gen.js --gen-debug-disassembler --out-lang=c
define dis-flavor
$(OUT_COMMON)/jump-dis-$(1).rs: $(OUT_COMMON)/out-$(2).json tables/gen.js Makefile
	$(GEN_JUMP_DIS) $(3) $$< > $$@ || rm -f $$@
$(OUT_COMMON)/debug-dis-$(1).c: $(OUT_COMMON)/out-$(2).json tables/gen.js Makefile
	$(GEN_DEBUG_DIS) $(3) $$< > $$@ || rm -f $$@
$(OUT_COMMON)/jump-dis-all: $(OUT_COMMON)/jump-dis-$(1).rs
$(OUT_COMMON)/debug-dis-all: $(OUT_COMMON)/debug-dis-$(1).c
endef
$(eval $(call dis-flavor,arm,ARM,-n _arm))
$(eval $(call dis-flavor,thumb,ARM,-n _thumb))
$(eval $(call dis-flavor,thumb2,ARM,-n _thumb2))

$(OUT_COMMON)/jump-dis-all:
	touch $@
$(OUT_COMMON)/debug-dis-all:
	touch $@

$(OUT)/llvm-debug-dis-c.o: dis/llvm-debug-dis-c.c $(OUT_COMMON)/debug-dis-all
	clang -c -o $@ $< -O3
$(OUT)/lib%.a: $(OUT)/%.o
	ar rcs $@ $<


endif # end USE_LLVM

DYLD_THING_FOR_LIBCLANG  := \
	DYLD_LIBRARY_PATH=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib:$$DYLD_LIBRARY_PATH

$(OUT)/cargo-build: Cargo.toml
	test -e Cargo.lock && cargo update || true
	$(DYLD_THING_FOR_LIBCLANG) \
	RUSTC=$(RUSTC) \
	cargo build $(CARGO_BUILD_FLAGS)
	touch $@ # xxx

XC_LIBCLANG_PATH := /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib
externals/rust-bindgen/bindgen: $(OUT)/cargo-build
	dir=~/.cargo/git/checkouts; \
	bg=$$(ls -t $$dir | grep '^rust-bindgen-' | head -n 1); \
	$(XRUSTC) -o $@ $$dir/$$bg/master/src/bin/bindgen.rs -L$(XC_LIBCLANG_PATH) -C link-args='-rpath $(XC_LIBCLANG_PATH)'

$(OUT)/static-bindgen: externals/rust-bindgen/bindgen Makefile staticize.sh
	./staticize.sh "$@" "$<"

$(OUT)/macho_bind.rs: fmt/macho_bind.h fmt/bind_defs.rs Makefile externals/mach-o/* fmt/bindgen.py
	$(DYLD_THING_FOR_LIBCLANG) \
	python2.7 fmt/bindgen.py "$<" -match mach/ -match mach-o/ -Iexternals/mach-o \
		-force-type 'LC_' u32 \
		> "$@" || (rm -f "$@"; false)

$(call define_crate,$(LIB),exec,fmt/exec.rs fmt/arch.rs fmt/reloc.rs,util deps)
$(call define_crate,$(LIB),macho_bind,$(OUT)/macho_bind.rs,util deps)
$(call define_crate,$(LIB),macho,fmt/macho.rs fmt/dyldcache.rs,macho_bind exec util deps)
$(call define_crate,$(LIB),macho_dsc_extraction,fmt/macho_dsc_extraction.rs,macho exec util deps)
$(call define_crate,$(LIB),raw_binary,fmt/raw_binary.rs,exec util deps)
$(OUT)/elf_bind.rs: externals/elf/elf.h fmt/bind_defs.rs Makefile fmt/bindgen.py
	$(DYLD_THING_FOR_LIBCLANG) \
	python2.7 fmt/bindgen.py "$<" -match elf.h \
		-enum2string 'EM_' 'e_machine_to_str' 'lower strip_prefix' \
		-enum2string 'DT_' 'd_tag_to_str' '' \
		> "$@" || (rm -f "$@"; false)
$(call define_crate,$(LIB),elf_bind,$(OUT)/elf_bind.rs,util deps)
$(call define_crate,$(LIB),elf,fmt/elf.rs,elf_bind exec util deps)
$(call define_crate,$(LIB),dis,dis/dis.rs,exec util deps)
ifneq ($(USE_LLVM),)
$(call define_crate,$(LIB),llvm_jump_dis,dis/llvm_jump_dis.rs,dis,jump-dis-all deps)
$(call define_crate,$(LIB),llvm_debug_dis,dis/llvm_debug_dis.rs,dis deps,$(OUT)/libllvm-debug-dis-c.a)
$(call define_crate,$(LIB),llvmdis,dis/llvmdis.rs,dis util deps)
endif

$(call define_crate,$(LIB),db,db/sexpr.rs,util deps)

$(call define_crate,bin,exectool,tool/exectool.rs fmt/execall.rs dis/disall.rs,macho macho_dsc_extraction elf raw_binary dis $(if $(USE_LLVM),llvmdis llvm_debug_dis,) deps)
$(call define_crate,bin,yasce,tool/yasce.rs,macho macho_dsc_extraction deps)

clean:
	rm -rf $(OUT) $(TARGET_DIR)/$(CARGO_BUILD_TYPE)

extraclean: clean
	rm -rf tables/llvm-tblgen Cargo.lock

$(NOT_OUT)/%: FORCE
	@echo "wrong output directory ('make outopt/foo OPT=1' or 'make out/foo')"
	@exit 1
FORCE:
