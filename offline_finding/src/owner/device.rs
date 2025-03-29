use aes_gcm::{
    aead::{AeadMutInPlace, KeyInit},
    Key,
};
use anyhow::{anyhow, Result};
use p224::{elliptic_curve::ecdh, SecretKey};
use sha2_pre::Sha256;

use crate::protocol::{Aes, EncryptedReport, Location, OfflineFindingPublicKey, Report};

pub struct OwnerDevice();

impl OwnerDevice {
    pub fn decrypt_report(
        &self,
        secret_key: &SecretKey,
        encrypted_report: &EncryptedReport,
    ) -> Result<Report> {
        let accessory_public_key: OfflineFindingPublicKey = (&secret_key.public_key()).into();
        let finder_public_key = encrypted_report.ephemeral_public_key;

        let shared_secret = ecdh::diffie_hellman(
            secret_key.to_nonzero_scalar(),
            finder_public_key.as_affine(),
        );

        let mut symmetric_key = [0u8; 32];
        let entropy: [u8; 28] = accessory_public_key.into();

        ansi_x963_kdf::derive_key_into::<Sha256>(
            shared_secret.raw_secret_bytes(),
            &entropy,
            &mut symmetric_key,
        )?;

        let (encryption_key, iv) = symmetric_key.split_at(16);

        let key = Key::<Aes>::from_slice(encryption_key);
        let mut cipher = Aes::new(key);

        let mut decrypted_location = encrypted_report.encrypted_location;
        cipher
            .decrypt_in_place_detached(
                iv.into(),
                &[],
                &mut decrypted_location,
                (&encrypted_report.tag).into(),
            )
            .map_err(|e| anyhow!(e))?;

        Ok(Report {
            timestamp: encrypted_report.timestamp,
            confidence: encrypted_report.confidence,
            location: Location::from_bytes(&decrypted_location).unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use p224::SecretKey;

    use crate::{finder::FinderDevice, owner::OwnerDevice, protocol::Location};

    use super::*;

    #[test]
    fn test_decrypt_encrypted_report() {
        let finder_device = FinderDevice();

        let location = Location {
            latitude: 37,
            longitude: 73,
            horizontal_accuracy: 5,
            status: 0,
        };

        let accessory_secret_key = SecretKey::random(&mut rand::rngs::OsRng);
        let accessory_public_key =
            OfflineFindingPublicKey::from(&accessory_secret_key.public_key());

        let encrypted_report = finder_device
            .encrypt_report(
                &mut rand::rngs::OsRng,
                &accessory_public_key,
                &Report {
                    timestamp: 1000,
                    confidence: 1,
                    location: location.clone(),
                },
            )
            .unwrap();

        let owner_device = OwnerDevice();
        let decrypted_report = owner_device
            .decrypt_report(&accessory_secret_key, &encrypted_report)
            .unwrap();

        assert_eq!(decrypted_report.timestamp, encrypted_report.timestamp);
        assert_eq!(decrypted_report.confidence, encrypted_report.confidence);
        assert_eq!(decrypted_report.location, location);
    }
}
