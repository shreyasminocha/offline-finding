mod data;
mod encrypted;
mod location;
mod payload;
mod serialized;

pub use data::ReportData;
pub use encrypted::EncryptedReportPayload;
pub use location::{Coordinate, Location};
pub use payload::ReportPayloadAsReceived;
pub use serialized::SerializedEncryptedReportPayload;

pub trait ReportPayload {}

// base64-encoded serialized payload, as fetched from apple servers
// ideally we wouldn't do this and do a `TryFrom` impl on the 'serialized form' struct
#[cfg(feature = "std")]
impl ReportPayload for std::string::String {}
