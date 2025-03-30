use anyhow::Result;
use p224::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, PublicKey,
};

#[derive(Debug)]
pub struct Report {
    pub timestamp: u32,
    pub confidence: u8,
    pub location: Location,
}

#[derive(Debug)]
pub struct ReceivedReport {
    pub timestamp: u32,
    pub confidence: u8,
    pub finder_public_key: PublicKey,
    pub location: Location,
}

#[derive(Debug)]
pub struct EncryptedReport {
    pub timestamp: u32,
    pub confidence: u8,
    /// Finder device's ephemeral public key from the keypair that was used during the location encryption process.
    pub finder_public_key: PublicKey,
    pub encrypted_location: [u8; 10],
    pub tag: [u8; 16],
}

pub enum SerializedEncryptedReport {
    LegacyFormat([u8; 88]),
    NewFormat([u8; 89]), // https://github.com/MatthewKuKanich/FindMyFlipper/issues/61#issuecomment-2065003410
}

impl From<[u8; 88]> for SerializedEncryptedReport {
    fn from(value: [u8; 88]) -> Self {
        SerializedEncryptedReport::LegacyFormat(value)
    }
}

impl From<[u8; 89]> for SerializedEncryptedReport {
    fn from(value: [u8; 89]) -> Self {
        SerializedEncryptedReport::NewFormat(value)
    }
}

impl TryFrom<&[u8]> for SerializedEncryptedReport {
    type Error = ();

    fn try_from(value: &[u8]) -> core::result::Result<Self, Self::Error> {
        if let Ok(array) = TryInto::<[u8; 88]>::try_into(value) {
            Ok(SerializedEncryptedReport::LegacyFormat(array))
        } else if let Ok(array) = TryInto::<[u8; 89]>::try_into(value) {
            Ok(SerializedEncryptedReport::NewFormat(array))
        } else {
            Err(())
        }
    }
}

#[cfg(feature = "std")]
impl From<SerializedEncryptedReport> for crate::std::vec::Vec<u8> {
    fn from(value: SerializedEncryptedReport) -> Self {
        match value {
            SerializedEncryptedReport::LegacyFormat(array) => array.to_vec(),
            SerializedEncryptedReport::NewFormat(array) => array.to_vec(),
        }
    }
}

impl EncryptedReport {
    pub fn serialize(&self) -> SerializedEncryptedReport {
        let point = self.finder_public_key.to_encoded_point(false);

        let mut output = [0; 88];
        output[0..4].copy_from_slice(&self.timestamp.to_le_bytes());
        output[4] = self.confidence;
        output[5..62].copy_from_slice(point.as_bytes());
        output[62..72].copy_from_slice(&self.encrypted_location);
        output[72..88].copy_from_slice(&self.tag);

        SerializedEncryptedReport::LegacyFormat(output)
    }

    pub fn deserialize(data: SerializedEncryptedReport) -> Result<Self> {
        let bytes = match data {
            SerializedEncryptedReport::LegacyFormat(bs) => bs,
            SerializedEncryptedReport::NewFormat(bs) => bs[1..].try_into().expect("89 - 1 == 88"),
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
        let encrypted_report = EncryptedReport {
            timestamp: 0,
            confidence: 0,
            finder_public_key: ecdh::EphemeralSecret::random(&mut rand::rngs::OsRng).public_key(),
            encrypted_location: [0; 10],
            tag: [0; 16],
        };

        let serialized: Vec<u8> = encrypted_report.serialize().into();
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
