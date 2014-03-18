RUSTSRC := /usr/src/rust
RUSTC := rustc -O -C prefer-dynamic --crate-type dylib
DYNAMICLIB := -dynamiclib
cratefile = lib$(1).dylib
define define_crate
cf := $(call cratefile,$(1))
sources := $(2)
deps := $(3)
$$(cf): $$(sources) Makefile $$(foreach 1,$$(deps),$$(cratefile))
	$(RUSTC) -o $$(cf) $$(firstword $$(sources))
all: $$(cf)
endef

all: $(call cratefile,llvmshim)
$(call cratefile,llvmshim): llvmshim.cpp
	echo 'extern crate rustc;' > rcpath.rs && link_args=$$($(RUSTC) -Z print-link-args rcpath.rs) && $(CC) -O3 $(DYNAMICLIB) -o $@ $< -I$(RUSTSRC)/src/llvm/include $$(echo "$$link_args" | sed "s/cc link args: //;s/'//g" | xargs -n 1 echo | fgrep -v rcpath)
	rm -f rcpath.rs

$(eval $(call define_crate,llvmhelp,llvmhelp.rs,))

clean:
	rm -f *.dylib *.so rcpath.rs
