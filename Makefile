RUSTSRC := /usr/src/rust
RUSTC := rustc -O -C prefer-dynamic --crate-type dylib -L.
ANOTHER_LLVM := /opt/local/libexec/llvm-3.4/include/
cratefile = lib$(1).dylib
define define_crate
cf := $(call cratefile,$(1))
sources := $(2)
deps := $(3)
$$(cf): $$(sources) Makefile $$(foreach 1,$$(deps),$$(cratefile))
	$(RUSTC) $$(firstword $$(sources))
	ln -nfs lib$(1)-* $$@
all: $$(cf)
endef

all: $(call cratefile,llvmshim)
$(call cratefile,llvmshim): llvmshim.cpp llvmshim.rs Makefile
	$(CC) -std=c++11 -c -o llvmshim_cpp.o -I$(RUSTSRC)/src/llvm/include -I$(ANOTHER_LLVM) -D __STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS $<
	$(RUSTC) llvmshim.rs -C link-args=llvmshim_cpp.o
	ln -nfs libllvmshim-* $@

$(eval $(call define_crate,llvmhelp,llvmhelp.rs,llvmshim))

clean:
	rm -f *.dylib *.so rcpath.rs
