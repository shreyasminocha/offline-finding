use aes_gcm::{aead::AeadMutInPlace, Key, KeyInit};
use anyhow::{anyhow, Result};
#[cfg(feature = "std")]
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use chrono::{DateTime, Duration, Utc};
use p224::{
    ecdh,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, PublicKey, SecretKey,
};
use sha2_pre::Sha256;

#[cfg(feature = "std")]
use crate::protocol::OfflineFindingPublicKey;
use crate::protocol::{Aes, Location};

use super::{ReportPayload, ReportPayloadAsReceived, SerializedEncryptedReportPayload};

/// An offline finding report in its encrypted form.
///
/// This can be thought of as the encrypted version of [`ReportPayloadAsReceived`].
pub struct EncryptedReportPayload {
    /// Timestamp from when the report was constructed.
    pub timestamp: DateTime<Utc>,
    /// Supposedly the degree of confidence in the accuracy of the location.
    pub confidence: u8,
    /// The finder device's ephemeral public key corresponding to the keypair that was used during the encryption of this report.
    pub finder_public_key: PublicKey,
    /// The AES-GCM ciphertext for the encryption of the finder device's [`Location`].
    pub encrypted_location: [u8; 10],
    /// The AES-GCM tag corresponding to the encrypted location.
    pub tag: [u8; 16],
}

impl EncryptedReportPayload {
    /// Decrypt an encrypted report using the accessory's private key to complete the ECDH key exchange.
    ///
    /// In theory, a finder device's public key could also be used to decrypt the encrypted payload, but in practice, it's unlikely to ever be necessary.
    pub fn decrypt(&self, accessory_private_key: &SecretKey) -> Result<ReportPayloadAsReceived> {
        let finder_public_key = self.finder_public_key;

        let shared_secret = ecdh::diffie_hellman(
            accessory_private_key.to_nonzero_scalar(),
            finder_public_key.as_affine(),
        );

        let mut symmetric_key = [0u8; 32];
        let finder_public_key_point = self.finder_public_key.to_encoded_point(false);
        let entropy = finder_public_key_point.as_bytes();

        ansi_x963_kdf::derive_key_into::<Sha256>(
            shared_secret.raw_secret_bytes().as_slice(),
            entropy,
            &mut symmetric_key,
        )?;

        let (encryption_key, iv) = symmetric_key.split_at(16);

        let key = Key::<Aes>::from_slice(encryption_key);
        let mut cipher = Aes::new(key);

        let mut decrypted_location = self.encrypted_location; // bytes are `Copy`'ed here
        cipher
            .decrypt_in_place_detached(iv.into(), &[], &mut decrypted_location, (&self.tag).into())
            .map_err(|e| anyhow!(e))?;

        Ok(ReportPayloadAsReceived {
            timestamp: self.timestamp,
            confidence: self.confidence,
            finder_public_key: (&finder_public_key).into(),
            location: Location::from_bytes(&decrypted_location).unwrap(),
        })
    }

    /// Serialize the encrypted report into its canonical 88-byte representation.
    pub fn serialize(&self) -> SerializedEncryptedReportPayload {
        let seconds: u32 = (self.timestamp - Duration::days(11323))
            .timestamp()
            .try_into()
            .unwrap();
        let point = self.finder_public_key.to_encoded_point(false);

        let mut output = [0; 88];
        output[0..4].copy_from_slice(&seconds.to_be_bytes());
        output[4] = self.confidence;
        output[5..62].copy_from_slice(point.as_bytes());
        output[62..72].copy_from_slice(&self.encrypted_location);
        output[72..88].copy_from_slice(&self.tag);

        // TODO: support the new format too?
        SerializedEncryptedReportPayload::LegacyFormat(output)
    }

    /// Deserialize the encrypted report from the canonical 88- or 89-byte representation.
    pub fn deserialize(data: SerializedEncryptedReportPayload) -> Result<Self> {
        let bytes = match data {
            SerializedEncryptedReportPayload::LegacyFormat(bs) => bs,
            // TODO: what does the new byte encode?
            SerializedEncryptedReportPayload::NewFormat(bs) => {
                bs[1..].try_into().expect("89 - 1 == 88")
            }
        };

        let seconds = u32::from_be_bytes(bytes[0..4].try_into().expect("correctly-sized slice"));
        let duration_since_epoch =
            Duration::new(seconds as i64, 0).unwrap() + Duration::days(11323);
        let timestamp = DateTime::from_timestamp(duration_since_epoch.num_seconds(), 0).unwrap();

        let confidence = bytes[4];
        let finder_public_key =
            PublicKey::from_encoded_point(&EncodedPoint::from_bytes(&bytes[5..62]).unwrap())
                .unwrap();
        let encrypted_location = &bytes[62..72];
        let tag = &bytes[72..88];

        Ok(Self {
            timestamp,
            confidence,
            finder_public_key,
            encrypted_location: encrypted_location
                .try_into()
                .expect("correctly-sized slice"),
            tag: tag.try_into().expect("correctly-sized slice"),
        })
    }
}

impl ReportPayload for EncryptedReportPayload {}

#[cfg(feature = "std")]
impl core::fmt::Debug for EncryptedReportPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptedReportPayload")
            .field("timestamp", &self.timestamp)
            .field("confidence", &self.confidence)
            .field(
                "finder_public_key",
                &b64.encode(OfflineFindingPublicKey::from(&self.finder_public_key).0),
            )
            .field(
                "encrypted_location",
                &hex::encode_upper(self.encrypted_location),
            )
            .field("tag", &hex::encode_upper(self.encrypted_location))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;

    use crate::{
        finder::FinderDevice,
        protocol::{Coordinate, Location, OfflineFindingPublicKey, ReportData},
    };

    use super::*;

    #[test]
    fn test_decrypt_encrypted_report() {
        let accessory_secret_key = SecretKey::random(&mut rand::rngs::OsRng);
        let accessory_public_key =
            OfflineFindingPublicKey::from(&accessory_secret_key.public_key());

        let location = Location {
            latitude: Coordinate(37.0),
            longitude: Coordinate(73.0),
            horizontal_accuracy: 5,
            status: 0,
        };

        let finder_device = FinderDevice();
        let encrypted_report = finder_device
            .encrypt_report(
                &mut rand::rngs::OsRng,
                &accessory_public_key,
                &ReportData {
                    timestamp: DateTime::parse_from_rfc3339("2025-01-01T16:39:57Z")
                        .expect("it's a valid date")
                        .into(),
                    confidence: 1,
                    location: location.clone(),
                },
            )
            .unwrap();

        let decrypted_report = encrypted_report.decrypt(&accessory_secret_key).unwrap();

        assert_eq!(decrypted_report.timestamp, encrypted_report.timestamp);
        assert_eq!(decrypted_report.confidence, encrypted_report.confidence);
        assert_eq!(decrypted_report.location, location);
    }
}
