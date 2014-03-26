# This Makefile is public domain.

RUSTSRC := /usr/src/rust
RUSTC := rustc -O -C prefer-dynamic -L.
LLVM := $(RUSTSRC)/src/llvm
ANOTHER_LLVM_INC := /opt/local/libexec/llvm-3.4/include/ # ...
cratefile_dylib = lib$(1).dylib
cratefile_bin = $(1)
define define_crate
kind = $(1)
name := $(2)
cf := $$(call cratefile_$$(kind),$$(name))
sources := $(3)
deps := $(4)
$$(cf): $$(sources) Makefile $$(foreach 1,$$(deps),$$(cratefile_$$(kind)))
	$(RUSTC) --crate-type $$(kind) $$(firstword $$(sources))
ifneq ($$(kind),bin)
	ln -nfs lib$(1)-* $$@
endif

all: $$(cf)

test-$$(name): $$(sources) Makefile $$(foreach 1,$$(deps),$$(cratefile))
	$(RUSTC) -g --crate-type dylib --test -o $$@ $$(firstword $$(sources))

# separate rule to avoid deleting it on failure
do-test-$$(name): test-$$(name)
	./$$<

test: do-test-$$(name)
clean-$$(name):
	rm -f test-$$(name)
clean: clean-$$(name)
endef

all: $(call cratefile_dylib,llvmshim)
$(call cratefile_dylib,llvmshim): llvmshim.cpp llvmshim.rs Makefile
	$(CC) -std=c++11 -c -o llvmshim_cpp.o -I$(LLVM)/include -I$(ANOTHER_LLVM_INC) -D __STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS $<
	$(RUSTC) --crate-type dylib llvmshim.rs -C link-args=llvmshim_cpp.o
	ln -nfs libllvmshim-* $@

$(eval $(call define_crate,dylib,llvmhelp,llvmhelp.rs,llvmshim))

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

clean:
	rm -rf *.dylib *.so *.o *.dSYM tables/out-*

distclean: clean
	rm -f tables/llvm-tblgen
