use p224::SecretKey;

use crate::protocol::OfflineFindingPublicKey;

mod legit_airtag;

pub use legit_airtag::LegitAirtag;

pub trait Accessory {
    fn iter_our_keys(&self) -> impl Iterator<Item = (SecretKey, OfflineFindingPublicKey)>;
}
