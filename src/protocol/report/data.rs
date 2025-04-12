use chrono::{DateTime, Utc};

use super::Location;

#[derive(Debug)]
pub struct ReportData {
    pub timestamp: DateTime<Utc>,
    pub confidence: u8,
    pub location: Location,
}
