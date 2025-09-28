export NODE_INSTALL_OWNER ?= root

export NODE_INSTALL_GROUP ?= adm

export NODE_INSTALL_CFG_PERMS ?= 0640

define make_rules
$(2): $(1)/$(2)/Makefile
	make -C $(1)/$(2)
build-$(2) : $(2)

static-checks-build-$(2):
	make -C $(1)/$(2) static-checks-build

check-$(2) : $(2)
	make -C $(1)/$(2) check

vendor-$(2) : $(1)/$(2)/Makefile
	make -C $(1)/$(2) vendor

clean-$(2) : $(1)/$(2)/Makefile
	make -C $(1)/$(2) clean

install-$(2) : $(2)
	make -C  $(1)/$(2) install

test-$(2) : $(2)
	make -C $(1)/$(2) test

.PHONY: \
	$(2) \
	build-$(2) \
	clean-$(2) \
	check-$(2) \
	vendor-$(2) \
	test-$(2) \
	install-$(2)
endef

define make_component_rules
$(eval $(call make_rules,bin,$(1)))
endef

define make_all_rules
$(1)-all: $(foreach c,$(COMPONENTS),$(1)-$(c))

.PHONY: $(1) $(1)-all
endef

define create_all_rules

all: $(1) $(2)

#Create rules for all components
$(foreach c,$(1),$(eval $(call make_component_rules,$(c))))

#Create rules for all tools
$(foreach c,$(2),$(eval $(call make_all_rules,$(c))))

#Create the "-all" rules.
$(foreach a,$(3),$(eval $(call make_all_rules,$(a))))

$(3) : % : %-all

endef

BUILD_TYPE ?= release

HOST_ARCH = $(shell uname -m)
ARCH ?= $(HOST_ARCH)

LIBC ?= gnu
ifneq ($(LIBC),musl)
	ifeq ($(LIBC),gnu)
		override LIBC = gnu
	else
		$(error "Error: A non supported LIBC value was passed. Supported values are musl and gnu")
	endif
endif

EXTRA_RUSTFLAGS :=

TRIPLE = $(ARCH)-unknown-linux-$(LIBC)

CWD := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

standard_rust_check:
	@echo "standard rust check..."
	cargo fmt -- --check
	cargo clippy --all-target --all-features --release \
		-- \
		-D warnings

define INSTALL_FILE_FULL
	sudo install \
		--mode $3 \
		--owner $(NODE_INSTALL_OWNER) \
		--group $(NODE_INSTALL_GROUP) \
		-D $1 $2/$(notdir $1) || exit 1;
endef

define INSTALL_CONFIG
	$(call INSTALL_FILE_FULL,$1,$2,$(NODE_INSTALL_CFG_PERMS))
endef
