PROJECT_NAME = Peer Node
PROJECT_URL = https://github.com/billionairiam/peernode
PROJECT_COMPONENT = node-agent

TARGET = $(PROJECT_COMPONENT)

COMMIT_NO := $(shell git rev-parse HEAD 2>/dev/null || true)
COMMIT := $(if $(shell git status --porcelain --untracked-files=no 2>/dev/null || true),${COMMIT_NO}-dirty,${COMMIT_NO})
COMMIT_MSG = $(if $(COMMIT),$(COMMIT),unknown)
AGENT_PATH := node-agent

export VERSION_COMMIT := $(if $(COMMIT),$(VERSION)-$(COMMIT),$(VERSION))

include ../../utils.mk

TARGET_PATH = target/$(TRIPLE)/$(BUILD_TYPE)/$(TARGET)

DESTDIR ?=

BINDIR := /usr/bin

INIT := no

GENERATED_CODE = src/version.rs

AGENT_NAME=$(TARGET)
API_VERSION=0.0.1
AGENT_VERSION=$(VERSION)

GENERATED_REPLACEMENTS= \
	AGENT_NAME \
	AGENT_VERSION \
	API_VERSION \
	BINDIR \
	COMMIT \
	VERSION_COMMIT \
	AGENT_PATH
GENERATED_FILES :=

GENERATED_FILES += $(GENERATED_CODE)

define get_command_version
$(shell printf "%s: %s\\n" $(1) "$(or $(shell $(1) --version 2>/dev/null), (not available))")
endef

define get_toolchain_version
$(shell printf "%s: %s\\n" "toolchain" "$(or $(shell rustup show active-toolchain 2>/dev/null), (unknown))")
endef

define INSTALL_FILE
	install -D -m 644 $1 $(DESTDIR)$2/$1 || exit 1;
endef

.DEFAULT_GOAL := default

default: $(TARGET) show-header

static-checks-build: $(GENERATED_CODE)

$(TARGET): $(GENERATED_CODE) $(TARGET_PATH)

$(TARGET_PATH): show-summary
	@RUSTFLAGS="$(EXTRA_RUSTFLAGS) --deny warnings" cargo build --target $(TRIPLE) $(if $(findstring release,$(BUILD_TYPE)),--release) $(EXTRA_RUSTFEATURES)

$(GENERATED_FILES): %: %.in 
	@sed $(foreach r,$(GENERATED_REPLACEMENTS),-e 's|@$r@|$($r)|g') "$<" > "$@"

optimize: show-summary show-header
	@RUSTFLAGS="-C link-arg=-s $(EXTRA_RUSTFEATURES) --deny warnings" cargo build --target $(TRIPLE) $(if $(findstring release,$(BUILD_TYPE)),--release) $(EXTRA_RUSTFEATURES)

clean:
	@cargo clean
	@rm -f $(GENERATED_FILES)

vendor:
	@cargo vendor

test: $(GENERATED_FILES)
	@RUST_LIB_BACKTRACE=0 RUST_BACKTRACE=1 cargo test --all --target $(TRIPLE) $(EXTRA_RUSTFEATURES) -- --nocapture

check: $(GENERATED_FILES) standard_rust_check

run:
	@cargo run --target $(TRIPLE)

show-header:
	@printf "%s - version %s (commit %s)\n\n" "$(TARGET)" "$(VERSION)" "$(COMMIT_MSG)"

show-summary: show-header
	@printf "project\n"
	@printf "  name $(PROJECT_NAME)\n"
	@printf "  url $(PROJECT_URL)\n"
	@printf "  component: $(PROJECT_COMPONENT)\n"
	@printf "target: $(TARGET)\n"
	@printf "architecture: \n"
	@printf "  host: $(ARCH)\n"
	@printf "rust:\n"
	@printf "  %s\n" "$(call get_command_version,cargo)"
	@printf "  %s\n" "$(call get_command_version,rustc)"
	@printf "  %s\n" "$(call get_command_version,rustup)"
	@printf "  %s\n" "$(call get_toolchain_version)"
	@printf "\n"

help: Makefile show-summary
	@echo "==========================Help============================="
	@echo "Variables"
	@sed -n 's/^##VAR//p' $< | sort
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##TARGET//p' $< | sort

TARPAULIN_ARGS:=-v --workspace
install-tarpaulin:
	cargo install cargo-tarpaulin

HAS_TARPAULIN:=$(shell cargo --list | grep tarpaulin 2>/dev/null)
check_tarpaulin:
ifndef HAS_TARPAULIN
	$(error "tarpaulin is not available please: run make install-tarpaulin")
else
	$(info Ok: tarpaulin installed)
endif

codecov: check_tarpaulin
	cargo tarpaulin $(TARPAULIN_ARGS)

codecov-html: check_tarpaulin
	cargo tarpaulin $(TARPAULIN_ARGS) -o Html

.PHONY: \
	help \
	optimize \
	show-header \
	show-summary \
	vendor
