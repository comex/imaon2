# This Makefile is public domain.

RUSTSRC := /usr/src/rust
RUSTC := rustc -O -C prefer-dynamic -L.
LLVM := $(RUSTSRC)/src/llvm
ANOTHER_LLVM := /opt/local/libexec/llvm-3.4
cratefile_dylib = lib$(1).dylib
cratefile_bin = $(1)

all:

define define_crate_
kind := $(1)
name := $(2)
cf := $$(call cratefile_$$(kind),$$(name))
sources := $(3)
deps := $(4)

$$(cf): $$(sources) Makefile $$(foreach 1,$$(deps),$$(cratefile_$$(kind)))
	$(RUSTC) --crate-type $$(kind) $$<
ifneq ($$(kind),bin)
	ln -nfs lib$(2)-* $$@
endif

all: $$(cf)

test-$$(name): $$(sources) Makefile $$(foreach 1,$$(deps),$$(cratefile))
	$(RUSTC) -g --crate-type dylib --test -o $$@ $$<

# separate rule to avoid deleting it on failure
do-test-$$(name): test-$$(name)
	./$$<

test: do-test-$$(name)
endef
define_crate = $(eval $(define_crate_))

$(call define_crate,dylib,util,util.rs,)

all: $(call cratefile_dylib,llvmshim)
$(call cratefile_dylib,llvmshim): llvmshim.cpp llvmshim.rs Makefile
	$(CC) -std=c++11 -c -o llvmshim_cpp.o -I$(LLVM)/include -I$(ANOTHER_LLVM)/include -D __STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS $<
	$(RUSTC) --crate-type dylib llvmshim.rs -C link-args=llvmshim_cpp.o
	ln -nfs libllvmshim-* $@

$(call define_crate,dylib,llvmhelp,llvmhelp.rs,llvmshim)

# deps here are wonky
tables/llvm-tblgen: tables/build-tblgen.sh $(LLVM)
	cd tables; ./build-tblgen.sh "$(LLVM)"

LLVM_TARGETS := X86/X86 ARM/ARM Sparc/Sparc Mips/Mips AArch64/AArch64 PowerPC/PPC
define td_target_
tables/out-$(1).td: $(LLVM)/lib/Target/$(1) $(LLVM) tables/llvm-tblgen
	tables/llvm-tblgen -I$(LLVM)/include -I$$< $$</$(2).td -o $$@
tables/out-$(1).json: tables/out-$(1).td tables/untable.js tables/untable.peg
	node tables/untable.js $$< $$@
out-td: tables/out-$(1).td tables/out-$(1).json
endef
td_target = $(call td_target_,$(word 1,$(1)),$(word 2,$(1)))
$(foreach target,$(LLVM_TARGETS),$(eval $(call td_target,$(subst /, ,$(target)))))
all: out-td

$(call define_crate,dylib,util_syntax,util_syntax.rs,)

externals/rust-bindgen/bindgen: externals/rust-bindgen/bindgen.rs externals/rust-bindgen/*.rs
	rustc -o $@ $< -C link-args=-L$(ANOTHER_LLVM)/lib

fmt/macho_bind.rs: fmt/macho_bind.h fmt/bind_defs.rs Makefile externals/mach-o/* externals/rust-bindgen/bindgen fmt/bindgen.sh
	fmt/bindgen.sh "$<" "$@" -match mach-o/ -Iexternals/mach-o
$(call define_crate,dylib,exec,fmt/exec.rs fmt/arch.rs,)
$(call define_crate,dylib,macho,fmt/macho.rs fmt/macho_bind.rs,exec util)
fmt/elf_bind.rs: externals/elf/elf.h fmt/bind_defs.rs Makefile externals/rust-bindgen/bindgen fmt/bindgen.sh
	fmt/bindgen.sh "$<" "$@" -match mach-o/ -Iexternals/mach-o
$(call define_crate,dylib,elf,fmt/elf.rs fmt/elf_bind.rs,exec util)

clean:
	rm -rf *.dylib *.so *.o *.dSYM tables/out-*
	rm -f test-* fmt/*_bind.rs

distclean: clean
	rm -f tables/llvm-tblgen
