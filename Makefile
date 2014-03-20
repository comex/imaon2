# This Makefile is public domain.

RUSTSRC := /usr/src/rust
RUSTC := rustc -O -C prefer-dynamic --crate-type dylib -L.
LLVM := $(RUSTSRC)/src/llvm
ANOTHER_LLVM_INC := /opt/local/libexec/llvm-3.4/include/ # ...
cratefile = lib$(1).dylib
define define_crate
name := $(1)
cf := $(call cratefile,$$(name))
sources := $(2)
deps := $(3)
$$(cf): $$(sources) Makefile $$(foreach 1,$$(deps),$$(cratefile))
	$(RUSTC) $$(firstword $$(sources))
	ln -nfs lib$(1)-* $$@

all: $$(cf)

test-$$(name): $$(sources) Makefile $$(foreach 1,$$(deps),$$(cratefile))
	$(RUSTC) -g --test -o $$@ $$(firstword $$(sources))

# separate rule to avoid deleting it on failure
do-test-$$(name): test-$$(name)
	./$$<

test: do-test-$$(name)
clean-$$(name):
	rm -f test-$$(name)
clean: clean-$$(name)
endef

all: $(call cratefile,llvmshim)
$(call cratefile,llvmshim): llvmshim.cpp llvmshim.rs Makefile
	$(CC) -std=c++11 -c -o llvmshim_cpp.o -I$(LLVM)/include -I$(ANOTHER_LLVM_INC) -D __STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS $<
	$(RUSTC) llvmshim.rs -C link-args=llvmshim_cpp.o
	ln -nfs libllvmshim-* $@

$(eval $(call define_crate,llvmhelp,llvmhelp.rs,llvmshim))

# deps here are wonky
tables/llvm-tblgen: tables/build-tblgen.sh $(LLVM)
	cd tables; ./build-tblgen.sh "$(LLVM)"

LLVM_TARGETS := X86 ARM Sparc Mips AArch64
tables/out-%.td: $(LLVM)/lib/Target/% $(LLVM) tables/llvm-tblgen
	tables/llvm-tblgen -I$(LLVM)/include -I$< $</$*.td -o $@
out-td: $(foreach target,$(LLVM_TARGETS),tables/out-$(target).td)
all: out-td

clean:
	rm -rf *.dylib *.so *.o *.dSYM tables/out-*

distclean: clean
	rm -f tables/llvm-tblgen
