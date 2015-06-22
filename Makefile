# This Makefile is public domain.


rustc-extern = --extern $(1)=`ls -t target/debug/deps/lib$(1)*.rlib | head -n 1`

OUT := ./out
$(shell mkdir -p $(OUT))
RUSTSRC := /usr/src/rust
RUSTC := rustc -Ltarget/debug/deps $(call rustc-extern,regex) $(call rustc-extern,log) -L. -L$(OUT)
LLVM := $(RUSTSRC)/src/llvm
cratefile_dylib = $(OUT)/lib$(1).dylib
cratefile_rlib = $(OUT)/lib$(1).rlib
cratefile_bin = $(OUT)/$(1)

ifeq ($(OPT),1)
LIB := rlib
RUSTC := $(RUSTC) -O
RUSTCFLAGS_bin := -C lto
else
LIB := dylib
RUSTC := $(RUSTC) -C codegen-units=1 -C prefer-dynamic
ifneq ($(NDEBUG),1)
RUSTC := $(RUSTC) -g
endif
endif

RUSTC := $(RUSTC) -Z no-landing-pads

all:

define define_crate_
# 1=kind 2=name 3=sources 4=deps
cratefile-$(2) := $$(call cratefile_$(1),$(2))

$$(cratefile-$(2)): $(3) Makefile $$(foreach dep,$(4),$$(cratefile-$$(dep))) cargo-build
	# specify -o explicitly?
	$(RUSTC) $(RUSTCFLAGS_$(1)) --crate-type $(1) --out-dir $(OUT) $$<
	#cd $(OUT); ln -nfs $$(call cratematch_$(1),$(2)) ../$$@

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

cargo-build: Cargo.toml
	test -a Cargo.lock && cargo update || true
	cargo build
	touch $@ # xxx

XC_LIBCLANG_PATH := /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib
externals/rust-bindgen/bindgen: cargo-build
	dir=~/.cargo/git/checkouts; \
	bg=$$(ls -t $$dir | grep '^rust-bindgen-' | head -n 1); \
	$(RUSTC) -o $@ $$dir/$$bg/master/src/bin/bindgen.rs -L$(XC_LIBCLANG_PATH) -C link-args='-rpath $(XC_LIBCLANG_PATH)'

$(OUT)/static-bindgen: externals/rust-bindgen/bindgen Makefile staticize.sh
	./staticize.sh "$@" "$<"

$(OUT)/macho_bind.rs: fmt/macho_bind.h fmt/bind_defs.rs Makefile externals/mach-o/* fmt/bindgen.py
	python fmt/bindgen.py "$<" -match mach/ -match mach-o/ -Iexternals/mach-o > "$@"
$(call define_crate,$(LIB),exec,fmt/exec.rs fmt/arch.rs,util)
$(call define_crate,$(LIB),macho,fmt/macho.rs $(OUT)/macho_bind.rs fmt/dyldcache.rs,exec util)
$(call define_crate,$(LIB),raw_binary,fmt/raw_binary.rs,exec util)
$(OUT)/elf_bind.rs: externals/elf/elf.h fmt/bind_defs.rs Makefile fmt/bindgen.py
	python fmt/bindgen.py "$<" -match elf.h > "$@"
$(call define_crate,$(LIB),elf,fmt/elf.rs $(OUT)/elf_bind.rs,exec util)
$(call define_crate,$(LIB),dis,dis/dis.rs,exec)
$(call define_crate,$(LIB),llvmdis,dis/llvmdis.rs,dis util)

$(call define_crate,bin,exectool,fmt/exectool.rs fmt/execall.rs,macho elf raw_binary)

clean:
	rm -rf out cargo-build Cargo.lock target

extraclean: clean
	rm -rf tables/llvm-tblgen
