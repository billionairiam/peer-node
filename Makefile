COMPONENTS =

COMPONENTS += agent
COMPONENTS += ctd-decoder

STANDARD_TARGETS = build check clean install static-checks-build test vendor

default: all

include utils.mk

# Create the rules
$(eval $(call create_all_rules,$(COMPONENTS),$(STANDARD_TARGETS)))

.PHONY: \
	all \
	default
