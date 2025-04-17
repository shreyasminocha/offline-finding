#[cfg(feature = "std")]
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use chrono::{DateTime, Utc};

use crate::protocol::OfflineFindingPublicKey;

use super::{Location, ReportPayload};

pub struct ReportPayloadAsReceived {
    pub timestamp: DateTime<Utc>,
    pub confidence: u8,
    pub finder_public_key: OfflineFindingPublicKey,
    pub location: Location,
}

impl ReportPayload for ReportPayloadAsReceived {}

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
