use super::{EncryptedReportPayload, ReportPayloadAsReceived, SerializedEncryptedReportPayload};
use anyhow::{bail, Result};
use p224::SecretKey;
use std::vec::Vec;

/// Size of a publish chunk as found empirically
const PUBLISH_SIZE: usize = 120;

/// parse_publish converts the raw bytes uploaded to a server into usable data
pub fn parse_publish(data: &[u8]) -> Result<Vec<EncryptedReportPayload>> {
    // Heinrich et al. Section 6.3
    if data[0..3] != [0x0f, 0x8a, 0xe0] {
        bail!("First bytes did not match header");
    }
    let len = data[3] + 1;
    let data = &data[4..];

    if data.len() / PUBLISH_SIZE != len as usize {
        bail!("Length byte did not match given length");
    }
    if data.len() % PUBLISH_SIZE != 0 {
        bail!("Reports were not exactly 135 bytes long")
    }

    let mut reports = Vec::new();
    for chunk in data.chunks_exact(PUBLISH_SIZE) {
        let serialized =
            SerializedEncryptedReportPayload::from(TryInto::<[u8; 88]>::try_into(&chunk[32..120])?);
        let report = EncryptedReportPayload::deserialize(serialized)?;
        reports.push(report);
    }
    Ok(reports)
}

/// parse_and_decrypt_publish converts raw bytes uploaded to the server into decrypted reports
pub fn parse_and_decrypt_publish(
    data: &[u8],
    key: &SecretKey,
) -> Result<Vec<ReportPayloadAsReceived>> {
    let encrypted_reports = parse_publish(data)?;
    let mut reports = Vec::new();
    for enc in encrypted_reports.iter() {
        let dec = enc.decrypt(key)?;
        reports.push(dec);
    }
    Ok(reports)
}
