use core::marker::Sized;

use p224::{elliptic_curve::rand_core::CryptoRngCore, SecretKey};

use crate::keys::{OfflineFindingPublicKey, SymmetricKey};

pub trait Accessory {
    fn new(private_key: SecretKey, symmetric_key: SymmetricKey) -> Self
    where
        Self: Sized;
    fn random(csprng: &mut impl CryptoRngCore) -> (Self, SecretKey, SymmetricKey)
    where
        Self: Sized;
    fn rotate_keys(&mut self);
    fn get_current_public_key(&self) -> OfflineFindingPublicKey;
}
