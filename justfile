run:
	cargo run

check:
	cargo hack clippy --feature-powerset
	cargo fmt -- --check

test:
	cargo test
