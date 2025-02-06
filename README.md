# Needle

Based on the reverse engineering done by [Open Haystack](https://github.com/seemoo-lab/openhaystack).

# Getting Started

- Install [probe-rs](https://probe.rs/)
- Connect the [Microbit V2](https://microbit.org/) to your computer
- Run `probe-rs erase --allow-erase-all --chip nrf52833_xxAA`
- Run `probe-rs download --verify --binary-format hex --chip nRF52833_xxAA s140_nrf52_7.3.0_softdevice.hex`
- Those two commands only need to be run once

- Run `cargo run` to build and install the software

Disclaimer: do no use this for evil
