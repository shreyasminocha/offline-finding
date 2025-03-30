run:
	cargo run

check:
	cargo clippy
	cargo fmt -- --check

test:
	cargo test
