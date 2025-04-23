use chrono::{DateTime, Utc};

use super::Location;

/// The data included in an offline finding report.
///
/// Unlike [`ReportPayloadAsReceived`](super::payload::ReportPayloadAsReceived), this struct does not include the finder's public key.
/// This is intended to be a finder-agnostic representation of the report data and may be used by a
/// finder to prepare an encrypted report.
#[derive(Debug)]
pub struct ReportData {
    /// Timestamp from when the report was constructed.
    pub timestamp: DateTime<Utc>,
    /// Supposedly the degree of confidence in the accuracy of the location.
    pub confidence: u8,
    /// The geographical location of the finder device.
    pub location: Location,
}
