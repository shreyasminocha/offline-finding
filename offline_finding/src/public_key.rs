use p224::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use sha2::{Digest, Sha256};

pub struct OfflineFindingPublicKey([u8; 28]);

impl OfflineFindingPublicKey {
    pub fn to_ble_address_bytes_be(&self) -> [u8; 6] {
        let mut addr_bytes_be: [u8; 6] = self
            .0
            .get(0..6)
            .expect("six < twenty-eight")
            .try_into()
            .expect("there are exactly six elements in the slice");
        addr_bytes_be[0] |= 0b11000000;

        addr_bytes_be
    }

    pub fn to_ble_advertisement_data(&self) -> [u8; 29] {
        // From the OpenHaystack paper
        let mut data: [u8; 29] = [
            0x4c, 0x00,       // Apple company ID
            0x12,       // Offline finding
            25,         // Length of following data
            0b11100000, // Status (e.g. battery level)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, // last 22 key bytes
            0, // first two bits of key
            0, // Hint. Indicates something about the lost device? 0x00 for iOS reports
        ];
        data[5..27].copy_from_slice(&self.0[6..]);
        data[27] = self.0[0] >> 6;

        data
    }

    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0).0
    }
}

impl From<&SecretKey> for OfflineFindingPublicKey {
    fn from(value: &SecretKey) -> Self {
        // equation 4
        let ad_public_key = value.public_key();

        let ad_public_key_point = ad_public_key.to_encoded_point(true);
        let key: [u8; 28] = ad_public_key_point
            .x()
            .unwrap()
            .as_slice()
            .try_into()
            .expect("the x coordinate of a P224 point must be 28 bytes long");

        Self(key)
    }
}

#[cfg(test)]
mod tests {
    use const_decoder::{decode, Decoder};

    use super::*;

    #[test]
    fn test_to_ble_address_bytes_be() {
        let public_key: [u8; 28] =
            decode!(Decoder::Base64, b"/j3eaoofkmPIV4hAJTIh2qmE9s1W3Y4PoBoohg==");
        let of_public_key = OfflineFindingPublicKey(public_key);
        let mac = of_public_key.to_ble_address_bytes_be();

        assert_eq!(mac.as_slice(), decode!(Decoder::Hex, b"FE3DDE6A8A1F"));
    }
}
