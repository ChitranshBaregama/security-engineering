# Build and run everything. This is what CI runs.
.PHONY: all test attacks clean

all: test attacks

test:
	@$(MAKE) -s -C tests

attacks:
	@$(MAKE) -s -C attacks/length-extension
	@echo
	@$(MAKE) -s -C attacks/timing

clean:
	@$(MAKE) -s -C tests clean
	@$(MAKE) -s -C attacks/length-extension clean
	@$(MAKE) -s -C attacks/timing clean
