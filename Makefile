.PHONY: conformance test-rust list

conformance:
	python3 conformance/runner.py

test-rust:
	cargo test --manifest-path impls/rust/Cargo.toml

list:
	@printf '%s\n' impls/*
