RUSTC := rustc -O -C prefer-dynamic --crate-type dylib
cratefile = lib$(1).dylib
define define_crate
cf := $(call cratefile,$(1))
sources := $(2)
deps := $(3)
$$(cf): $$(sources) Makefile $$(foreach 1,$$(deps),$$(cratefile))
	$(RUSTC) -o $$(cf) $$(firstword $$(sources))
all: $$(cf)
endef
$(eval $(call define_crate,llvmhelp,llvmhelp.rs,))
