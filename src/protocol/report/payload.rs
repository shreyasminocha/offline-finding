#[cfg(feature = "std")]
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
#[cfg(feature = "std")]
use geojson::{Feature, Geometry, JsonObject, Value};

use chrono::{DateTime, Utc};

use super::{Location, ReportPayload};
use crate::protocol::OfflineFindingPublicKey;

/// An offline finding report including the ephemeral public key of the finder device that
/// generated the report.
///
/// This can be thought of as the unencrypted (or decrypted) version of [`EncryptedReportPayload`](super::super::EncryptedReportPayload).
#[cfg_attr(feature = "std", derive(serde::Serialize))]
pub struct ReportPayloadAsReceived {
    /// Timestamp from when the report was constructed.
    pub timestamp: DateTime<Utc>,
    /// Supposedly the degree of confidence in the accuracy of the location.
    pub confidence: u8,
    /// The finder device's ephemeral public key corresponding to the keypair that was used during the encryption of this report.
    pub finder_public_key: OfflineFindingPublicKey,
    /// The finder device's geographical location and the associated metadata.
    pub location: Location,
}

impl ReportPayload for ReportPayloadAsReceived {}

impl ReportPayloadAsReceived {
    /// converts to a geojson object
    #[cfg(feature = "std")]
    pub fn to_geojson(&self) -> Feature {
        let json_props: JsonObject =
            serde_json::from_str(&serde_json::to_string(self).unwrap()).unwrap();
        let loc = &self.location;
        Feature {
            bbox: None,
            geometry: Some(Geometry::new(Value::Point(vec![
                loc.longitude.0 as f64,
                loc.latitude.0 as f64,
            ]))),
            id: None,
            properties: Some(json_props),
            foreign_members: None,
        }
    }
}

#[cfg(feature = "std")]
impl core::fmt::Debug for ReportPayloadAsReceived {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReportPayloadAsReceived")
            .field("timestamp", &self.timestamp)
            .field("confidence", &self.confidence)
            .field("finder_public_key", &b64.encode(self.finder_public_key.0))
            .field("location", &self.location)
            .finish()
    }
}
