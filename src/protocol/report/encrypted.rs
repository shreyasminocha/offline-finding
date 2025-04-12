use core::fmt::Debug;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use chrono::{DateTime, Duration, Utc};
use p224::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, PublicKey, SecretKey,
};

use crate::{owner::OwnerDevice, protocol::OfflineFindingPublicKey};

use super::{ReportPayload, ReportPayloadAsReceived, SerializedEncryptedReportPayload};

pub struct EncryptedReportPayload {
    pub timestamp: DateTime<Utc>,
    pub confidence: u8,
    /// Finder device's ephemeral public key from the keypair that was used during the location encryption process.
    pub finder_public_key: PublicKey,
    pub encrypted_location: [u8; 10],
    pub tag: [u8; 16],
}

impl EncryptedReportPayload {
    pub fn decrypt(&self, private_key: SecretKey) -> Result<ReportPayloadAsReceived> {
        let owner_device = OwnerDevice(); // todo: do this stuff here directly
        owner_device.decrypt_report(&private_key, &self)
    }

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

        SerializedEncryptedReportPayload::LegacyFormat(output)
    }

    pub fn deserialize(data: SerializedEncryptedReportPayload) -> Result<Self> {
        let bytes = match data {
            SerializedEncryptedReportPayload::LegacyFormat(bs) => bs,
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

impl Debug for EncryptedReportPayload {
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
                &hex::encode_upper(&self.encrypted_location),
            )
            .field("tag", &hex::encode_upper(&self.encrypted_location))
            .finish()
    }
}
