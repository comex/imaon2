# This Makefile is public domain.



RUSTSRC := /usr/src/rust
LLVM := $(RUSTSRC)/src/llvm

ifeq ($(OPT),1)
LIB := rlib
RUSTC := $(RUSTC) -O --cfg opt
RUSTCFLAGS_bin := -C lto
CARGO_BUILD_TYPE := release
CARGO_BUILD_FLAGS := --release
OUT := ./outrel
else
LIB := dylib
RUSTC := $(RUSTC) -C codegen-units=1 -C prefer-dynamic
ifneq ($(NDEBUG),1)
RUSTC := $(RUSTC) -g
endif
CARGO_BUILD_TYPE := debug
CARGO_BUILD_FLAGS :=
OUT := ./out
endif

$(shell mkdir -p $(OUT))
cratefile_dylib = $(OUT)/lib$(1).dylib
cratefile_rlib = $(OUT)/lib$(1).rlib
cratefile_bin = $(OUT)/$(1)

rustc-extern = --extern $(1)=`ls -t target/$(CARGO_BUILD_TYPE)/deps/lib$(1)-*.*lib | head -n 1`
RUSTC := rustc -Ltarget/$(CARGO_BUILD_TYPE)/deps $(if $(USE_LLVM),$(call rustc-extern,autollvm),) -L. -L$(OUT) $(RUSTC)

RUSTC := $(RUSTC) -Z no-landing-pads

all:

define define_crate_
# 1=kind 2=name 3=sources 4=deps
cratefile-$(2) := $$(call cratefile_$(1),$(2))

# specify -o explicitly?
$$(cratefile-$(2)): $(3) Makefile $$(foreach dep,$(4),$$(cratefile-$$(dep))) $(OUT)/cargo-build
	$(RUSTC) $(RUSTCFLAGS_$(1)) --crate-type $(1) --out-dir $(OUT) $$<

all: $$(cratefile-$(2))

out/test-$(2): $(3) Makefile $$(foreach dep,$(4),$$(cratefile-$$(dep)))
	$(RUSTC) -g --crate-type dylib --test -o $$@ $$<

# separate rule to avoid deleting it on failure
do-test-$(2): out/test-$(2)
	./$$<

test: do-test-$(2)
endef
define_crate = $(eval $(define_crate_))

$(call define_crate,rlib,macros,macros.rs,)
$(call define_crate,$(LIB),bsdlike_getopts,bsdlike_getopts.rs,)
$(call define_crate,$(LIB),util,util.rs,macros bsdlike_getopts)

ifneq ($(USE_LLVM),)
# deps here are wonky
tables/llvm-tblgen: tables/build-tblgen.sh $(LLVM)
	cd tables; ./build-tblgen.sh "$(LLVM)"

LLVM_TARGETS := X86/X86 ARM/ARM Sparc/Sparc Mips/Mips AArch64/AArch64 PowerPC/PPC
define td_target_
$(OUT)/out-$(1).td: $(LLVM)/lib/Target/$(1) $(LLVM) tables/llvm-tblgen
	tables/llvm-tblgen -I$(LLVM)/include -I$$< $$</$(2).td -o $$@
$(OUT)/out-$(1).json: $(OUT)/out-$(1).td tables/untable.js tables/untable.peg
	node tables/untable.js $$< $$@
out-td: $(OUT)/out-$(1).td $(OUT)/out-$(1).json
endef
td_target = $(call td_target_,$(word 1,$(1)),$(word 2,$(1)))
$(foreach target,$(LLVM_TARGETS),$(eval $(call td_target,$(subst /, ,$(target)))))
all: out-td
endif

$(OUT)/cargo-build: Cargo.toml
	test -a Cargo.lock && cargo update || true
	DYLD_LIBRARY_PATH=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib:$$DYLD_LIBRARY_PATH \
	cargo build $(CARGO_BUILD_FLAGS)
	touch $@ # xxx

XC_LIBCLANG_PATH := /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib
externals/rust-bindgen/bindgen: $(OUT)/cargo-build
	dir=~/.cargo/git/checkouts; \
	bg=$$(ls -t $$dir | grep '^rust-bindgen-' | head -n 1); \
	$(RUSTC) -o $@ $$dir/$$bg/master/src/bin/bindgen.rs -L$(XC_LIBCLANG_PATH) -C link-args='-rpath $(XC_LIBCLANG_PATH)'

$(OUT)/static-bindgen: externals/rust-bindgen/bindgen Makefile staticize.sh
	./staticize.sh "$@" "$<"

$(OUT)/macho_bind.rs: fmt/macho_bind.h fmt/bind_defs.rs Makefile externals/mach-o/* fmt/bindgen.py
	python fmt/bindgen.py "$<" -match mach/ -match mach-o/ -Iexternals/mach-o > "$@"
$(call define_crate,$(LIB),exec,fmt/exec.rs fmt/arch.rs,util)
$(call define_crate,$(LIB),macho_bind,$(OUT)/macho_bind.rs,util)
$(call define_crate,$(LIB),macho,fmt/macho.rs fmt/dyldcache.rs,macho_bind exec util)
$(call define_crate,$(LIB),raw_binary,fmt/raw_binary.rs,exec util)
$(OUT)/elf_bind.rs: externals/elf/elf.h fmt/bind_defs.rs Makefile fmt/bindgen.py
	python fmt/bindgen.py "$<" -match elf.h \
		-enum2string 'EM_' 'e_machine_to_str' 'lower strip_prefix' \
		-enum2string 'DT_' 'd_tag_to_str' '' \
		> "$@"
$(call define_crate,$(LIB),elf_bind,$(OUT)/elf_bind.rs,util)
$(call define_crate,$(LIB),elf,fmt/elf.rs,elf_bind exec util)
$(call define_crate,$(LIB),dis,dis/dis.rs,exec util)
ifneq ($(USE_LLVM),)
$(call define_crate,$(LIB),llvmdis,dis/llvmdis.rs,dis util)
endif

$(call define_crate,$(LIB),db,db/sexpr.rs,util)

$(call define_crate,bin,exectool,exectool.rs fmt/execall.rs dis/disall.rs,macho elf raw_binary dis $(if $(USE_LLVM),llvmdis,))

clean:
	rm -rf $(OUT) target/$(CARGO_BUILD_TYPE)

extraclean: clean
	rm -rf tables/llvm-tblgen Cargo.lock
