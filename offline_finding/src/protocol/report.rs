use p224::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use serde::{ser::SerializeTuple, Deserialize, Serialize, Serializer};
use serde_with::serde_as;

pub struct Report {
    pub timestamp: u32,
    pub confidence: u8,
    pub location: Location,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct EncryptedReport {
    #[serde_as(as = "_")]
    pub timestamp: u32,
    #[serde_as(as = "_")]
    pub confidence: u8,
    #[serde(serialize_with = "serialize_public_key_57_bytes")]
    pub ephemeral_public_key: PublicKey,
    #[serde_as(as = "[_; 10]")]
    pub encrypted_location: [u8; 10],
    #[serde_as(as = "[_; 16]")]
    pub tag: [u8; 16],
}

fn serialize_public_key_57_bytes<S>(x: &PublicKey, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let point = x.to_encoded_point(false);

    let mut tup = s.serialize_tuple(57)?;
    for b in point.as_bytes() {
        tup.serialize_element(b)?;
    }
    tup.end()
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Location {
    pub latitude: u32,
    pub longitude: u32,
    pub horizontal_accuracy: u8,
    pub status: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    use bincode::serialize;
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

        let serialized = serialize(&encrypted_report).unwrap();
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

        let serialized = serialize(&location).unwrap();
        assert_eq!(serialized.len(), 10);
    }
}
