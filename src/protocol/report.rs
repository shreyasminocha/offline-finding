use core::fmt::Debug;

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use p224::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, PublicKey, SecretKey,
};

use crate::owner::OwnerDevice;

use super::OfflineFindingPublicKey;

pub trait ReportPayload {}

// base64-encoded serialized payload, as fetched from apple servers
#[cfg(feature = "std")]
impl ReportPayload for std::string::String {}

#[derive(Debug)]
pub struct ReportData {
    pub timestamp: u32,
    pub confidence: u8,
    pub location: Location,
}

pub struct ReportPayloadAsReceived {
    pub timestamp: u32,
    pub confidence: u8,
    pub finder_public_key: OfflineFindingPublicKey,
    pub location: Location,
}

impl ReportPayload for ReportPayloadAsReceived {}

impl Debug for ReportPayloadAsReceived {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReportPayloadAsReceived")
            .field("timestamp", &self.timestamp)
            .field("confidence", &self.confidence)
            .field("finder_public_key", &b64.encode(&self.finder_public_key.0))
            .field("location", &self.location)
            .finish()
    }
}

pub struct EncryptedReportPayload {
    pub timestamp: u32,
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

pub enum SerializedEncryptedReportPayload {
    LegacyFormat([u8; 88]),
    NewFormat([u8; 89]), // https://github.com/MatthewKuKanich/FindMyFlipper/issues/61#issuecomment-2065003410
}

impl From<[u8; 88]> for SerializedEncryptedReportPayload {
    fn from(value: [u8; 88]) -> Self {
        SerializedEncryptedReportPayload::LegacyFormat(value)
    }
}

impl From<[u8; 89]> for SerializedEncryptedReportPayload {
    fn from(value: [u8; 89]) -> Self {
        SerializedEncryptedReportPayload::NewFormat(value)
    }
}

impl TryFrom<&[u8]> for SerializedEncryptedReportPayload {
    type Error = ();

    fn try_from(value: &[u8]) -> core::result::Result<Self, Self::Error> {
        if let Ok(array) = TryInto::<[u8; 88]>::try_into(value) {
            Ok(SerializedEncryptedReportPayload::LegacyFormat(array))
        } else if let Ok(array) = TryInto::<[u8; 89]>::try_into(value) {
            Ok(SerializedEncryptedReportPayload::NewFormat(array))
        } else {
            Err(())
        }
    }
}

#[cfg(feature = "std")]
impl From<SerializedEncryptedReportPayload> for crate::std::vec::Vec<u8> {
    fn from(value: SerializedEncryptedReportPayload) -> Self {
        match value {
            SerializedEncryptedReportPayload::LegacyFormat(array) => array.to_vec(),
            SerializedEncryptedReportPayload::NewFormat(array) => array.to_vec(),
        }
    }
}

impl EncryptedReportPayload {
    pub fn serialize(&self) -> SerializedEncryptedReportPayload {
        let point = self.finder_public_key.to_encoded_point(false);

        let mut output = [0; 88];
        output[0..4].copy_from_slice(&self.timestamp.to_le_bytes());
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

        let timestamp = u32::from_le_bytes(bytes[0..4].try_into().expect("correctly-sized slice"));
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

#[derive(PartialEq, Debug, Clone)]
pub struct Location {
    pub latitude: f32,
    pub longitude: f32,
    pub horizontal_accuracy: u8,
    pub status: u8,
}

impl Location {
    pub fn to_bytes(&self) -> [u8; 10] {
        let mut output = [0; 10];

        // TODO: check that this works correctly and that a roundtrip works
        let latitude = (f64::from(self.latitude) * 10_000_000.0) as i32;
        let longitude = (f64::from(self.longitude) * 10_000_000.0) as i32;

        output[0..4].copy_from_slice(&latitude.to_be_bytes());
        output[4..8].copy_from_slice(&longitude.to_be_bytes());
        output[8] = self.horizontal_accuracy;
        output[9] = self.status;

        output
    }

    pub fn from_bytes(bytes: &[u8; 10]) -> Result<Self> {
        let latitude = i32::from_be_bytes(bytes[0..4].try_into().expect("correctly-sized slice"));
        let longitude = i32::from_be_bytes(bytes[4..8].try_into().expect("correctly-sized slice"));
        let horizontal_accuracy = bytes[8];
        let status = bytes[9];

        Ok(Self {
            latitude: (f64::from(latitude) / 10_000_000.0) as f32,
            longitude: (f64::from(longitude) / 10_000_000.0) as f32,
            horizontal_accuracy,
            status,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use p224::ecdh;

    #[test]
    fn test_serialized_encrypted_report_length() {
        let encrypted_report = EncryptedReportPayload {
            timestamp: 0,
            confidence: 0,
            finder_public_key: ecdh::EphemeralSecret::random(&mut rand::rngs::OsRng).public_key(),
            encrypted_location: [0; 10],
            tag: [0; 16],
        };

        let serialized: crate::std::vec::Vec<u8> = encrypted_report.serialize().into();
        assert_eq!(serialized.len(), 88);
    }

    #[test]
    fn test_serialized_location_length() {
        let location = Location {
            latitude: 0.0,
            longitude: 0.0,
            horizontal_accuracy: 0,
            status: 0,
        };

        let serialized = location.to_bytes();
        assert_eq!(serialized.len(), 10);
    }
}
