use anyhow::{Result};
use p224::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, PublicKey,
};

pub struct Report {
    pub timestamp: u32,
    pub confidence: u8,
    pub location: Location,
}

pub struct EncryptedReport {
    pub timestamp: u32,
    pub confidence: u8,
    pub ephemeral_public_key: PublicKey,
    pub encrypted_location: [u8; 10],
    pub tag: [u8; 16],
}

impl EncryptedReport {
    pub fn to_bytes(&self) -> [u8; 88] {
        let point = self.ephemeral_public_key.to_encoded_point(false);

        let mut output = [0; 88];
        output[0..4].copy_from_slice(&self.timestamp.to_le_bytes());
        output[4] = self.confidence;
        output[5..62].copy_from_slice(point.as_bytes());
        output[62..72].copy_from_slice(&self.encrypted_location);
        output[72..88].copy_from_slice(&self.tag);

        output
    }

    pub fn from_bytes(bytes: &[u8; 88]) -> Result<Self> {
        let timestamp = u32::from_le_bytes(bytes[0..4].try_into().expect("correctly-sized slice"));
        let confidence = bytes[4];
        let ephemeral_public_key =
            PublicKey::from_encoded_point(&EncodedPoint::from_bytes(&bytes[5..62]).unwrap()).unwrap();
        let encrypted_location = &bytes[62..72];
        let tag = &bytes[72..88];

        Ok(Self {
            timestamp,
            confidence,
            ephemeral_public_key,
            encrypted_location: encrypted_location
                .try_into()
                .expect("correctly-sized slice"),
            tag: tag.try_into().expect("correctly-sized slice"),
        })
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Location {
    pub latitude: u32,
    pub longitude: u32,
    pub horizontal_accuracy: u8,
    pub status: u8,
}

impl Location {
    pub fn to_bytes(&self) -> [u8; 10] {
        let mut output = [0; 10];
        output[0..4].copy_from_slice(&self.latitude.to_le_bytes());
        output[4..8].copy_from_slice(&self.longitude.to_le_bytes());
        output[8] = self.horizontal_accuracy;
        output[9] = self.status;

        output
    }

    pub fn from_bytes(bytes: &[u8; 10]) -> Result<Self> {
        let latitude = u32::from_le_bytes(bytes[0..4].try_into().expect("correctly-sized slice"));
        let longitude = u32::from_le_bytes(bytes[4..8].try_into().expect("correctly-sized slice"));
        let horizontal_accuracy = bytes[8];
        let status = bytes[9];

        Ok(Self {
            latitude,
            longitude,
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
            ephemeral_public_key: ecdh::EphemeralSecret::random(&mut rand::rngs::OsRng)
                .public_key(),
            encrypted_location: [0; 10],
            tag: [0; 16],
        };

        let serialized = encrypted_report.to_bytes();
        assert_eq!(serialized.len(), 88);
    }

    #[test]
    fn test_serialized_location_length() {
        let location = Location {
            latitude: 0,
            longitude: 0,
            horizontal_accuracy: 0,
            status: 0,
        };

        let serialized = location.to_bytes();
        assert_eq!(serialized.len(), 10);
    }
}
