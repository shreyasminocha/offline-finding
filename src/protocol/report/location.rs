use anyhow::Result;

/// The location information included in offline finding reports.
#[cfg_attr(feature = "std", derive(serde::Serialize))]
#[derive(PartialEq, Debug, Clone)]
pub struct Location {
    /// Latitude geographical coordinate.
    pub latitude: Coordinate,
    /// Longitude geographical coordinate.
    pub longitude: Coordinate,
    /// Degree of horizontal accuracy of the geographical coordinates.
    pub horizontal_accuracy: u8, // TODO: figure out precisely how to interpret this number.
    /// Byte encoding the status of the accessory, as included in the BLE advertisement.
    pub status: u8,
}

/// A geographical coordinate.
#[cfg_attr(feature = "std", derive(serde::Serialize))]
#[derive(PartialEq, Debug, Clone)]
pub struct Coordinate(pub f32);

impl Coordinate {
    /// Serialize the coordinate into FindMy's canonical 4-byte representation.
    fn to_bytes(&self) -> [u8; 4] {
        let int = (f64::from(self.0) * 10_000_000.0) as i32;
        int.to_be_bytes()
    }

    /// Deserialize a coordinate from FindMy's canonical 4-byte representation.
    fn from_bytes(bytes: &[u8; 4]) -> Self {
        let int = i32::from_be_bytes(*bytes);
        Self((f64::from(int) / 10_000_000.0) as f32)
    }
}

impl Location {
    /// Serialize the location into FindMy's canonical 10-byte representation.
    pub fn to_bytes(&self) -> [u8; 10] {
        let mut output = [0; 10];

        output[0..4].copy_from_slice(&self.latitude.to_bytes());
        output[4..8].copy_from_slice(&self.longitude.to_bytes());
        output[8] = self.horizontal_accuracy;
        output[9] = self.status;

        output
    }

    /// Attempt to deserialize the location from FindMy's canoncial 10-byte representation.
    pub fn from_bytes(bytes: &[u8; 10]) -> Result<Self> {
        let latitude =
            Coordinate::from_bytes(bytes[0..4].try_into().expect("correctly-sized slice"));
        let longitude =
            Coordinate::from_bytes(bytes[4..8].try_into().expect("correctly-sized slice"));
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

    #[test]
    fn test_coordinate_roundtrip() {
        let coord = Coordinate(3.1416);
        let bytes = coord.to_bytes();

        assert_eq!(coord, Coordinate::from_bytes(&bytes));
    }
}
