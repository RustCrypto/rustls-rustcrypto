check:
	cargo clippy --all-targets --all-features -- -D warnings

clean:
	rm -rf ./target

fix:
	cargo fix --allow-dirty
	cargo clippy --fix --allow-dirty
	cargo fmt

test:
	cargo test

cargo-update:
	rustup run 1.85.0 cargo update

.PHONY: check clean fix test cargo-update
