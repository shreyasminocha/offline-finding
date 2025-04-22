//! An interface for Apple's FindMy protocol and other offline-finding protocols.

#![no_std]
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

/// An offline finding accessory.
pub mod accessory;
/// An offline finding finder device.
pub mod finder;
/// An offline finding owner device.
pub mod owner;
/// Structs that capture aspects of Apple's FindMy protocol.
pub mod protocol;
/// Tools for interfacing with Apple's servers, e.g. to fetch FindMy reports.
#[cfg(feature = "std")]
pub mod server;

pub use p224;
