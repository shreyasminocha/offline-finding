/// The finder-agnostic report data.
mod data;
/// The encrypted form of a FindMy report.
mod encrypted;
/// Location and associated metadata as included in FindMy reports.
mod location;
/// The pre-encryption or post-decryption form of a FindMy report.
mod payload;
/// Batches of reports as uploaded to the server
mod publish;
/// The serialized form of an encrypted FindMy report.
mod serialized;

pub use data::ReportData;
pub use encrypted::EncryptedReportPayload;
pub use location::{Coordinate, Location};
pub use payload::ReportPayloadAsReceived;
pub use serialized::SerializedEncryptedReportPayload;

#[cfg(feature = "std")]
pub use publish::parse_publish;

/// A representation of the payload included in a FindMy report, e.g. encrypted or decrypted,
/// serialized or deserialized.
pub trait ReportPayload {}

// base64-encoded serialized payload, as fetched from apple servers
// ideally we wouldn't do this and do a `TryFrom` impl on the 'serialized form' struct
#[cfg(feature = "std")]
impl ReportPayload for std::string::String {}
