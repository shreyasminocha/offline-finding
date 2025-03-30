run:
	cargo run

check:
	cargo clippy
	cargo fmt -- --check

test:
	cargo test --target x86_64-unknown-linux-gnu
