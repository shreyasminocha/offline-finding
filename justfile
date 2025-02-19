run:
	cargo run

test:
	cargo test --target x86_64-unknown-linux-gnu -p offline-finding

prepare: erase flash-ble-stack

erase:
	probe-rs erase --allow-erase-all --chip nrf52833_xxAA

flash-ble-stack:
	probe-rs download --verify --binary-format hex --chip nRF52833_xxAA s140_nrf52_7.3.0_softdevice.hex
