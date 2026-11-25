# OnlyBlocks developer entry points. Every target wraps the stdlib-only
# Python 3.11+ harness in conformance/, so nothing here installs anything.
#
#   make list                        implementations that have a run.sh
#   make conformance                 offline golden suite, all implementations
#   make conformance IMPL=rust       ... or a subset: IMPL="rust go zig"
#   make security IMPL=c             hostile-input and zero-disk audit
#
# Run `make help` for the full list.

PYTHON ?= python3
IMPL ?=
IMPL_FLAGS := $(foreach slug,$(IMPL),--impl $(slug))

.DEFAULT_GOAL := help
.PHONY: help list conformance strict security self-test live bench test-rust

help:
	@printf '%s\n' \
	  'make list                     implementations with a run.sh' \
	  'make conformance [IMPL=...]   offline golden conformance suite' \
	  'make strict [IMPL=...]        same, requiring golden jsonParsed shapes' \
	  'make security [IMPL=...]      loopback hostile-input and zero-disk audit' \
	  'make self-test                exercise the harness with a dummy server' \
	  'make live [IMPL=...]          conformance plus live files.old-faithful.net probes' \
	  'make bench                    rewrite conformance/results.json (all impls, live)' \
	  'make test-rust                cargo unit tests for impls/rust' \
	  '' \
	  'IMPL takes one or more slugs, e.g. IMPL=rust or IMPL="c go zig".'

list:
	@for dir in impls/*/; do \
	  [ -f "$$dir/run.sh" ] && basename "$$dir"; \
	done; true

conformance:
	$(PYTHON) conformance/runner.py $(IMPL_FLAGS)

strict:
	$(PYTHON) conformance/runner.py --strict-parsed $(IMPL_FLAGS)

# No --report-out here: conformance/security_report.md is the committed
# all-implementation report, and a subset run must not overwrite it.
security:
	$(PYTHON) conformance/security_audit.py $(IMPL_FLAGS)

self-test:
	$(PYTHON) conformance/runner.py --self-test

live:
	$(PYTHON) conformance/runner.py --live $(IMPL_FLAGS)

bench:
	$(PYTHON) conformance/bench.py

test-rust:
	cargo test --offline --manifest-path impls/rust/Cargo.toml
