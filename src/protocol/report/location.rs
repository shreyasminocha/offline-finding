use anyhow::Result;

#[derive(PartialEq, Debug, Clone)]
pub struct Location {
    pub latitude: Coordinate,
    pub longitude: Coordinate,
    pub horizontal_accuracy: u8,
    pub status: u8,
}

#[derive(PartialEq, Debug, Clone)]
pub struct Coordinate(pub f32);

impl Coordinate {
    fn from_bytes(bytes: &[u8; 4]) -> Self {
        let int = i32::from_be_bytes(*bytes);
        Self((f64::from(int) / 10_000_000.0) as f32)
    }

    fn to_bytes(&self) -> [u8; 4] {
        let int = (f64::from(self.0) * 10_000_000.0) as i32;
        int.to_be_bytes()
    }
}

impl Location {
    pub fn to_bytes(&self) -> [u8; 10] {
        let mut output = [0; 10];

        output[0..4].copy_from_slice(&self.latitude.to_bytes());
        output[4..8].copy_from_slice(&self.longitude.to_bytes());
        output[8] = self.horizontal_accuracy;
        output[9] = self.status;

        output
    }

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
