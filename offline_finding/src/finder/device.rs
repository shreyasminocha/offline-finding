use aes_gcm::{
    aead::{AeadMutInPlace, KeyInit},
    Key,
};
use anyhow::{anyhow, Result};
use p224::{elliptic_curve::ecdh, PublicKey};
use rand_core::CryptoRngCore;
use sha2::Sha256;

use crate::protocol::{Aes, EncryptedReport, OfflineFindingPublicKey, Report};

pub struct FinderDevice();

impl FinderDevice {
    pub fn encrypt_report(
        &self,
        csprng: &mut impl CryptoRngCore,
        accessory_public_key: &OfflineFindingPublicKey,
        report: &Report,
    ) -> Result<EncryptedReport> {
        // (1) Generate a new ephemeral key
        let finder_secret = ecdh::EphemeralSecret::random(csprng);

        // (2) Perform ECDH using the ephemeral private key and the advertised public key
        let advertised_public_key: PublicKey = PublicKey::from(accessory_public_key);
        let shared_secret = finder_secret.diffie_hellman(&advertised_public_key);

        // (3) Derive a symmetric key with ANSI X.963 KDF on the shared secret
        let mut symmetric_key = [0u8; 32];
        let entropy: [u8; 28] = accessory_public_key.into();

        ansi_x963_kdf::derive_key_into::<Sha256>(
            shared_secret.raw_secret_bytes(),
            &entropy,
            &mut symmetric_key,
        )?;

        // (4) Use the first 16 bytes as the encryption key e′.
        // (5) Use the last 16 bytes as an initialization vector (IV).
        let (encryption_key, iv) = symmetric_key.split_at(16);

        // (6) Encrypt the location report under e′ and the IV with AES-GCM.
        let key = Key::<Aes>::from_slice(encryption_key);
        let mut cipher = Aes::new(key);

        let encoded_location = report.location.to_bytes();

        let mut encrypted_location = [0u8; 10];
        encrypted_location[0..10].copy_from_slice(&encoded_location);

        let tag = cipher
            .encrypt_in_place_detached(iv.into(), &[], &mut encrypted_location)
            .map_err(|e| anyhow!(e))?;

        Ok(EncryptedReport {
            timestamp: report.timestamp,
            confidence: report.confidence,
            ephemeral_public_key: finder_secret.public_key(),
            encrypted_location,
            tag: tag.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use p224::SecretKey;

    use crate::{finder::FinderDevice, owner::OwnerDevice, protocol::Location};

    use super::*;

    #[test]
    fn test_encrypt_report() {
        let finder_device = FinderDevice();

        let location = Location {
            latitude: 37,
            longitude: 73,
            horizontal_accuracy: 5,
            status: 0,
        };

        let report = Report {
            timestamp: 1000,
            confidence: 1,
            location: location.clone(),
        };

        let accessory_secret_key = SecretKey::random(&mut rand::rngs::OsRng);
        let accessory_public_key =
            OfflineFindingPublicKey::from(&accessory_secret_key.public_key());

        let encrypted_report = finder_device
            .encrypt_report(&mut rand::rngs::OsRng, &accessory_public_key, &report)
            .unwrap();

        assert_eq!(encrypted_report.timestamp, report.timestamp);
        assert_eq!(encrypted_report.confidence, report.confidence);

        let owner_device = OwnerDevice();
        let decrypted_report = owner_device
            .decrypt_report(&accessory_secret_key, &encrypted_report)
            .unwrap();

        assert_eq!(decrypted_report.location, location);
    }
}
