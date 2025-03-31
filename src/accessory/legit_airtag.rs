use num_bigint::BigUint;
use p224::{
    elliptic_curve::{bigint::Encoding, rand_core::CryptoRngCore, Curve},
    NistP224, SecretKey,
};
use sha2_pre::Sha256;

use crate::{accessory::Accessory, protocol::OfflineFindingPublicKey};

pub type SymmetricKey = [u8; 32];

pub struct LegitAirtag {
    master_beacon_private_key: SecretKey,
    master_beacon_symmetric_key: SymmetricKey,
    current_private_key: SecretKey,
    current_symmetric_key: SymmetricKey,
}

impl LegitAirtag {
    pub fn new(master_private_key: SecretKey, master_symmetric_key: SymmetricKey) -> Self {
        let mut accessory = LegitAirtag {
            master_beacon_private_key: master_private_key.clone(),
            master_beacon_symmetric_key: master_symmetric_key,
            current_private_key: master_private_key,
            current_symmetric_key: master_symmetric_key,
        };

        // important: generate initial ephemeral keys
        accessory.rotate_keys();

        accessory
    }

    pub fn random(csprng: &mut impl CryptoRngCore) -> Self {
        let master_beacon_private_key = SecretKey::random(csprng);

        let mut master_beacon_symmetric_key = [0; 32];
        csprng.fill_bytes(&mut master_beacon_symmetric_key);

        Self::new(master_beacon_private_key, master_beacon_symmetric_key)
    }

    pub fn get_master_symmetric_key(&self) -> &SymmetricKey {
        &self.master_beacon_symmetric_key
    }

    pub fn get_master_private_key(&self) -> &SecretKey {
        &self.master_beacon_private_key
    }

    fn rotate_keys(&mut self) {
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

    fn get_current_public_key(&self) -> OfflineFindingPublicKey {
        OfflineFindingPublicKey::from(&self.current_private_key)
    }
}

impl Accessory for LegitAirtag {
    fn iter_our_keys(&self) -> impl Iterator<Item = (SecretKey, OfflineFindingPublicKey)> {
        struct OurKeysIterator(LegitAirtag);

        impl Iterator for OurKeysIterator {
            type Item = (SecretKey, OfflineFindingPublicKey);

            fn next(&mut self) -> Option<Self::Item> {
                let item = (
                    self.0.current_private_key.clone(),
                    self.0.get_current_public_key(),
                );
                self.0.rotate_keys();

                Some(item)
            }
        }

        OurKeysIterator(LegitAirtag::new(
            self.master_beacon_private_key.clone(),
            self.master_beacon_symmetric_key,
        ))
    }
}

#[cfg(test)]
mod tests {
    use const_decoder::{decode, Decoder};
    use p224::elliptic_curve::sec1::ToEncodedPoint;

    use super::*;

    #[test]
    fn test_ephemeral_keys_not_same_as_master_ones() {
        let accessory = LegitAirtag::random(&mut rand::rngs::OsRng);

        assert_ne!(
            accessory.master_beacon_private_key,
            accessory.current_private_key
        );
        assert_ne!(
            accessory.master_beacon_symmetric_key,
            accessory.current_symmetric_key
        );
    }

    #[test]
    fn test_public_key_matches_current_private_key() {
        let accessory = LegitAirtag::random(&mut rand::rngs::OsRng);
        let accessory_public_key: [u8; 28] = accessory.get_current_public_key().into();

        let actual_public_key_point = accessory
            .current_private_key
            .public_key()
            .to_encoded_point(true);
        let actual_public_key = actual_public_key_point.as_bytes();
        let actual_public_key_without_sign_bit = &actual_public_key[1..];

        assert_eq!(
            actual_public_key_without_sign_bit,
            accessory_public_key.as_slice()
        );
    }

    #[test]
    fn test_key_rotation_matches_that_of_apple_airtags() {
        let mb_private_key = SecretKey::from_slice(&decode!(
            Decoder::Base64,
            b"KioqKioqKioqKioqKioqKioqKioqKioqKioqKg=="
        ))
        .unwrap();
        let mb_symmetric_key = decode!(
            Decoder::Base64,
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );

        let mut accessory = LegitAirtag::new(mb_private_key, mb_symmetric_key);

        // expected values from https://github.com/malmeloo/FindMy.py

        let actual: [u8; 28] = accessory.get_current_public_key().into();
        assert_eq!(
            actual,
            decode!(Decoder::Base64, b"77HRu4h48OgZIPO+eV9FOE8nPRZqpXT/FGbBAA==")
        );

        accessory.rotate_keys();
        let actual: [u8; 28] = accessory.get_current_public_key().into();
        assert_eq!(
            actual,
            decode!(Decoder::Base64, b"uoIdNzCdygG33VdHW9Sq6bnXqpuiT71qBZHuGA==")
        );

        accessory.rotate_keys();
        let actual: [u8; 28] = accessory.get_current_public_key().into();
        assert_eq!(
            actual,
            decode!(Decoder::Base64, b"qfsoe/hOu0Kbtkpbfs4dSnPmuGFZfHno1nNnRw==")
        );

        accessory.rotate_keys();
        let actual: [u8; 28] = accessory.get_current_public_key().into();
        assert_eq!(
            actual,
            decode!(Decoder::Base64, b"mR9Q7KjvRPUt56j6vZFwgtOHV1+tT6hOcBbjEA==")
        );
    }

    #[test]
    fn test_iterator_doesnt_include_master_key() {
        let accessory = LegitAirtag::random(&mut rand::rngs::OsRng);
        let mut iter = accessory.iter_our_keys();

        assert_ne!(iter.next().unwrap().0, accessory.master_beacon_private_key);
    }
}
