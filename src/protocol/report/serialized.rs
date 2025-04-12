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

#[cfg(test)]
mod tests {
    use super::super::{Coordinate, EncryptedReportPayload, Location};

    use chrono::DateTime;
    use p224::ecdh;

    #[test]
    fn test_serialized_encrypted_report_length() {
        let encrypted_report = EncryptedReportPayload {
            timestamp: DateTime::parse_from_rfc3339("2025-01-01T16:39:57Z")
                .expect("it's a valid date")
                .into(),
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
            latitude: Coordinate(0.0),
            longitude: Coordinate(0.0),
            horizontal_accuracy: 0,
            status: 0,
        };

        let serialized = location.to_bytes();
        assert_eq!(serialized.len(), 10);
    }
}
