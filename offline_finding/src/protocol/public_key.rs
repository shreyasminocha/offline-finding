use p224::{
    elliptic_curve::sec1::{CompressedPoint, Tag, ToEncodedPoint},
    NistP224, PublicKey, SecretKey,
};
use sha2::{Digest, Sha256};

const TWO_MOST_SIGNIFICANT_BITS_MASK: u8 = 0b11000000;

#[derive(Debug, Clone)]
pub struct OfflineFindingPublicKey([u8; 28]);

impl OfflineFindingPublicKey {
    pub fn to_ble_address_bytes_be(&self) -> [u8; 6] {
        let mut addr_bytes_be: [u8; 6] = self
            .0
            .get(0..6)
            .expect("six < twenty-eight")
            .try_into()
            .expect("there are exactly six elements in the slice");
        addr_bytes_be[0] |= TWO_MOST_SIGNIFICANT_BITS_MASK;

        addr_bytes_be
    }

    pub fn to_ble_advertisement_data(&self, metadata: BleAdvertisementMetadata) -> [u8; 29] {
        // From the OpenHaystack paper
        let mut data: [u8; 29] = [
            0x4c,
            0x00,            // Apple company ID
            0x12,            // Offline finding
            25,              // Length of following data
            metadata.status, // Status (e.g. battery level)
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,             // key[-22:]
            0,             // first two bits of key
            metadata.hint, // Hint. Indicates something about the lost device? 0x00 for iOS reports
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

impl From<&PublicKey> for OfflineFindingPublicKey {
    fn from(value: &PublicKey) -> Self {
        let ad_public_key_point = value.to_encoded_point(true);
        let key: [u8; 28] = ad_public_key_point
            .x()
            .unwrap()
            .as_slice()
            .try_into()
            .expect("the x coordinate of a P224 point must be 28 bytes long");

        Self(key)
    }
}

impl From<OfflineFindingPublicKey> for [u8; 28] {
    fn from(value: OfflineFindingPublicKey) -> Self {
        value.0
    }
}

impl From<&OfflineFindingPublicKey> for [u8; 28] {
    fn from(value: &OfflineFindingPublicKey) -> Self {
        value.0
    }
}

impl From<&OfflineFindingPublicKey> for PublicKey {
    fn from(value: &OfflineFindingPublicKey) -> Self {
        let mut data = [0u8; 29];
        data[0] = Tag::CompressedEvenY.into(); // `Tag::CompressedOddY` would also work fine
        data[1..29].copy_from_slice(&value.0);

        let compressed_point: CompressedPoint<NistP224> = data.into();

        PublicKey::try_from(compressed_point)
            .expect("assuming the original public key was valid, the new one should also be valid")
    }
}

pub struct BleAdvertisementMetadata {
    pub status: u8,
    pub hint: u8,
}

impl Default for BleAdvertisementMetadata {
    fn default() -> Self {
        Self {
            status: 0b11100000, // low battery
            hint: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use const_decoder::{decode, Decoder};

    use super::*;

    #[test]
    fn test_to_ble_address_bytes_be() {
        let public_key = decode!(Decoder::Base64, b"/j3eaoofkmPIV4hAJTIh2qmE9s1W3Y4PoBoohg==");
        let of_public_key = OfflineFindingPublicKey(public_key);
        let mac = of_public_key.to_ble_address_bytes_be();

        assert_eq!(mac.as_slice(), decode!(Decoder::Hex, b"FE3DDE6A8A1F"));
        assert_eq!(
            mac[0] & TWO_MOST_SIGNIFICANT_BITS_MASK,
            TWO_MOST_SIGNIFICANT_BITS_MASK
        );
    }

    #[test]
    fn test_to_ble_advertisement_data() {
        let public_key = [0; 28];
        let of_public_key = OfflineFindingPublicKey(public_key);
        let ad_data = of_public_key.to_ble_advertisement_data(BleAdvertisementMetadata::default());

        assert_eq!(ad_data[0..2], [0x4c, 0x00]);
        assert_eq!(ad_data[2], 0x12);
        assert_eq!(ad_data[3], 25);
        assert_eq!(ad_data[27], public_key[0] >> 6);
    }

    #[test]
    fn test_hash() {
        let public_key = decode!(Decoder::Base64, b"/j3eaoofkmPIV4hAJTIh2qmE9s1W3Y4PoBoohg==");
        let of_public_key = OfflineFindingPublicKey(public_key);

        assert_eq!(
            of_public_key.hash(),
            decode!(
                Decoder::Base64,
                b"RwPKNxB/wNDVZuQ8UEmKb2KHdakTHDNPTEvZ2kxRFvQ="
            )
        );
    }

    #[test]
    fn test_reconstructed_public_key_matches() {
        let public_key = [0; 28];
        let of_public_key = OfflineFindingPublicKey(public_key);

        let mac = of_public_key.to_ble_address_bytes_be();
        let ad_data = of_public_key.to_ble_advertisement_data(BleAdvertisementMetadata::default());

        let thing = ad_data[27] << 6;
        dbg!(thing, mac[0], mac[0] & !TWO_MOST_SIGNIFICANT_BITS_MASK);

        let reconstructed_public_key = [
            &[(ad_data[27] << 6) | (mac[0] & !TWO_MOST_SIGNIFICANT_BITS_MASK)],
            &mac[1..6],
            &ad_data[5..27],
        ]
        .concat();

        assert_eq!(reconstructed_public_key.len(), 28);
        assert_eq!(public_key.to_vec(), reconstructed_public_key);
    }
}
