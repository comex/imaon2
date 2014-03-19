# This Makefile is public domain.

RUSTSRC := /usr/src/rust
RUSTC := rustc -O -C prefer-dynamic --crate-type dylib -L.
ANOTHER_LLVM := /opt/local/libexec/llvm-3.4/include/
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
endef

all: $(call cratefile,llvmshim)
$(call cratefile,llvmshim): llvmshim.cpp llvmshim.rs Makefile
	$(CC) -std=c++11 -c -o llvmshim_cpp.o -I$(RUSTSRC)/src/llvm/include -I$(ANOTHER_LLVM) -D __STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS $<
	$(RUSTC) llvmshim.rs -C link-args=llvmshim_cpp.o
	ln -nfs libllvmshim-* $@

$(eval $(call define_crate,llvmhelp,llvmhelp.rs,llvmshim))

clean:
	rm -f *.dylib *.so rcpath.rs
