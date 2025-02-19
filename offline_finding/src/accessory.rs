use core::marker::Sized;

use p224::elliptic_curve::rand_core::CryptoRngCore;

use crate::keys::OfflineFindingPublicKey;

pub trait Accessory {
    fn random(csprng: &mut impl CryptoRngCore) -> Self
    where
        Self: Sized;
    fn rotate_keys(&mut self);
    fn get_current_public_key(&self) -> OfflineFindingPublicKey;
}
