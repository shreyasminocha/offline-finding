use p224::SecretKey;

use crate::protocol::OfflineFindingPublicKey;

/// An implementation of the Apple AirTag's key rotation scheme.
mod legit_airtag;

pub use legit_airtag::LegitAirtag;

/// An offline finding accessory that generates P224 key pairs and implements a key rotation scheme.
pub trait Accessory {
    /// Return an iterator over pairs of secret keys and the corresponding public keys.
    fn iter_our_keys(&self) -> impl Iterator<Item = (SecretKey, OfflineFindingPublicKey)>;
}
