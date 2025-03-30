use std::collections::HashMap;

use anyhow::Result;
use reqwest::{
    header::{HeaderMap, HeaderName},
    Client,
};

pub struct RemoteAnisetteProvider {
    endpoint: String,
    client: Client,
    anisette_data: HashMap<String, String>,
}

impl RemoteAnisetteProvider {
    pub const CLIENT: &str = "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>";
    // const TIMEZONE: &str = "EDT";
    // const LOCALE: &str = "en_US";
    const _ROUTER: &str = "17106176";

    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            client: reqwest::Client::new(),
            anisette_data: HashMap::new(),
        }
    }

    pub async fn get_headers(&mut self, with_client_info: bool) -> HeaderMap {
        let request = self.client.get(&self.endpoint);
        let response = request.send().await.unwrap();

        // TODO: cache this
        let response_body: serde_json::Map<String, serde_json::Value> =
            response.json().await.unwrap();

        self.anisette_data = HashMap::from_iter(
            response_body
                .into_iter()
                .map(|(k, v)| (k, v.as_str().unwrap().to_string())),
        );

        let mut headers = HeaderMap::with_capacity(15);
        for (k, v) in &self.anisette_data {
            headers.insert(
                k.as_str().parse::<HeaderName>().unwrap(),
                v.parse().unwrap(),
            );
        }

        if with_client_info {
            headers.insert(
                "X-Mme-Client-Info",
                Self::CLIENT.to_string().parse().unwrap(),
            );
            headers.insert(
                "X-Apple-App-Info",
                "com.apple.gs.xcode.auth".to_string().parse().unwrap(),
            );
            headers.insert(
                "X-Xcode-Version",
                "11.2 (11B41)".to_string().parse().unwrap(),
            );
        }

        headers
    }

    pub async fn get_cpd(&mut self) -> Result<plist::Dictionary> {
        let mut cpd = plist::Dictionary::new();
        cpd.insert("bootstrap".to_string(), plist::Value::Boolean(true));
        cpd.insert("icscrec".to_string(), plist::Value::Boolean(true));
        cpd.insert("pbe".to_string(), plist::Value::Boolean(false));
        cpd.insert("prkgen".to_string(), plist::Value::Boolean(true));
        cpd.insert(
            "svct".to_string(),
            plist::Value::String("iCloud".to_string()),
        );

        for (h, v) in self.get_headers(false).await {
            cpd.insert(
                h.unwrap().to_string(),
                plist::Value::String(v.to_str().unwrap().to_string()),
            );
        }

        Ok(cpd)
    }
}
