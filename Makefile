# This Makefile is public domain.

OUT := ./out
$(shell mkdir -p $(OUT))
RUSTSRC := /usr/src/rust
RUSTC := rustc -C codegen-units=2 -C rpath -C prefer-dynamic --out-dir $(OUT) -L. -L$(OUT)
LLVM := $(RUSTSRC)/src/llvm
ANOTHER_LLVM := /usr/local/opt/llvm/
cratefile_dylib = $(OUT)/lib$(1).dylib
cratematch_dylib = lib$(1)-*.dylib
cratefile_rlib = $(OUT)/lib$(1).rlib
cratefile_bin = $(OUT)/$(1)

all:

define define_crate_
# 1=kind 2=name 3=sources 4=deps
cratefile-$(2) := $$(call cratefile_$(1),$(2))

$$(cratefile-$(2)): $(3) Makefile $$(foreach dep,$(4),$$(cratefile-$$(dep)))
	$(RUSTC) --crate-type $(1) $$<
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

$(call define_crate,dylib,util,util.rs,)

cratefile-llvmshim := $(call cratefile_dylib,llvmshim)
all: $(cratefile-llvmshim)
$(cratefile-llvmshim): llvmshim.cpp llvmshim.rs Makefile
	$(CC) -std=c++11 -c -o $(OUT)/llvmshim_cpp.o -I$(LLVM)/include -I$(ANOTHER_LLVM)/include -D __STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS $<
	$(RUSTC) --crate-type dylib llvmshim.rs -C link-args=$(OUT)/llvmshim_cpp.o

#$(call define_crate,dylib,llvmhelp,llvmhelp.rs,llvmshim)

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

$(call define_crate,rlib,bindgen,externals/rust-bindgen/src/lib.rs $(glob externals/rust-bindgen/src/*.rs),)
externals/rust-bindgen/bindgen: externals/rust-bindgen/src/bin/bindgen.rs $(OUT)/libbindgen.rlib
	# I think the -rpath bit is a Homebrew bug.
	rustc -C rpath -o $@ $< -O -L $(OUT) -C link-args="-L$(ANOTHER_LLVM)/lib -rpath $(ANOTHER_LLVM)/lib"

$(OUT)/macho_bind.rs: fmt/macho_bind.h fmt/bind_defs.rs Makefile externals/mach-o/* externals/rust-bindgen/bindgen fmt/bindgen.py
	python fmt/bindgen.py "$<" -match mach/ -match mach-o/ -Iexternals/mach-o > "$@"
$(call define_crate,dylib,exec,fmt/exec.rs fmt/arch.rs,util)
$(call define_crate,dylib,macho,fmt/macho.rs $(OUT)/macho_bind.rs,exec util)
$(call define_crate,dylib,raw_binary,fmt/raw_binary.rs,exec util)
$(OUT)/elf_bind.rs: externals/elf/elf.h fmt/bind_defs.rs Makefile externals/rust-bindgen/bindgen fmt/bindgen.py
	python fmt/bindgen.py "$<" -match elf.h > "$@"
$(call define_crate,dylib,elf,fmt/elf.rs $(OUT)/elf_bind.rs,exec util)

$(call define_crate,bin,exectool,fmt/exectool.rs fmt/execall.rs,macho elf raw_binary)

clean:
	rm -rf out

extraclean: clean
	rm -f tables/llvm-tblgen
