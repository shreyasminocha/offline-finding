use num_bigint::BigUint;
use p224::{
    elliptic_curve::{bigint::Encoding, rand_core::CryptoRngCore, Curve},
    NistP224, SecretKey,
};
use sha2::Sha256;

use crate::public_key::OfflineFindingPublicKey;

pub type SymmetricKey = [u8; 32];

pub struct Accessory {
    master_beacon_private_key: SecretKey,
    master_beacon_symmetric_key: SymmetricKey,
    current_private_key: SecretKey,
    current_symmetric_key: SymmetricKey,
}

impl Accessory {
    pub fn new(private_key: SecretKey, symmetric_key: SymmetricKey) -> Self {
        let mut accessory = Accessory {
            master_beacon_private_key: private_key.clone(),
            master_beacon_symmetric_key: symmetric_key,
            current_private_key: private_key,
            current_symmetric_key: symmetric_key,
        };

        // important: generate initial ephemeral keys
        accessory.rotate_keys();

        accessory
    }

    pub fn random(csprng: &mut impl CryptoRngCore) -> (Self, SecretKey, SymmetricKey) {
        let master_beacon_private_key = SecretKey::random(csprng);

        let mut master_beacon_symmetric_key = [0; 32];
        csprng.fill_bytes(&mut master_beacon_symmetric_key);

        let mut accessory = Accessory {
            master_beacon_private_key: master_beacon_private_key.clone(),
            master_beacon_symmetric_key,
            current_private_key: master_beacon_private_key,
            current_symmetric_key: master_beacon_symmetric_key,
        };

        // important: generate initial ephemeral keys
        accessory.rotate_keys();

        let mb_private_key = accessory.master_beacon_private_key.clone();
        let mb_symmetric_key = accessory.master_beacon_symmetric_key;

        (accessory, mb_private_key, mb_symmetric_key)
    }

    pub fn rotate_keys(&mut self) {
        // equation 1
        let mut new_symmetric_key = [0u8; 32];
        ansi_x963_kdf::derive_key_into::<Sha256>(
            &self.current_symmetric_key,
            b"update",
            &mut new_symmetric_key,
        )
        .unwrap();

        // equation 2
        let mut uv = [0u8; 72];
        ansi_x963_kdf::derive_key_into::<Sha256>(&new_symmetric_key, b"diversify", &mut uv)
            .unwrap();

        let (u, v) = uv.split_at(36);

        // https://github.com/positive-security/find-you/blob/ab7a3a9/OpenHaystack/OpenHaystack/BoringSSL/BoringSSL.m#L194
        let order = &BigUint::from_bytes_be(&NistP224::ORDER.to_be_bytes());
        let order_minus_one = &(order - BigUint::from(1u8));
        let u_i = (BigUint::from_bytes_be(u) % order_minus_one) + BigUint::from(1u8);
        let v_i = (BigUint::from_bytes_be(v) % order_minus_one) + BigUint::from(1u8);

        let d_0 = BigUint::from_bytes_be(self.master_beacon_private_key.to_bytes().as_slice());

        // equation 3
        let d_i = (d_0 * u_i) + v_i;
        let d_i = d_i % order;
        let new_private_key = SecretKey::from_slice(&d_i.to_bytes_be()).unwrap();

        self.current_private_key = new_private_key;
        self.current_symmetric_key = new_symmetric_key;
    }

    pub fn get_current_public_key(&self) -> OfflineFindingPublicKey {
        OfflineFindingPublicKey::from(&self.current_private_key)
    }
}
