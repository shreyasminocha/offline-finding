use crate::{
    protocol::{OfflineFindingPublicKey, OfflineFindingPublicKeyId, ReportPayload},
    std::{
        collections::HashMap,
        env,
        string::{String, ToString},
        vec::Vec,
    },
};

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use chrono::{DateTime, Duration, Local, Utc};
use p224::SecretKey;
use rand::{rngs::OsRng, RngCore};
use reqwest::{header::HeaderMap, Client};
use serde::{Deserialize, Serialize};
use sha2_stable::Digest;
use srp::{client::SrpClient, groups::G_2048};

use crate::protocol::{EncryptedReportPayload, ReportPayloadAsReceived};

use super::anisette::RemoteAnisetteProvider;

/// Interface for interacting with Apple's FIndMy servers.
pub struct AppleReportsServer {
    client: Client,
    anisette_provider: RemoteAnisetteProvider,
}

impl AppleReportsServer {
    const ENDPOINT_GSA: &str = "https://gsa.apple.com/grandslam/GsService2";
    const _ENDPOINT_LOGIN_MOBILEME: &str = "https://setup.icloud.com/setup/iosbuddy/loginDelegates";

    // 2fa auth endpoints
    const _ENDPOINT_2FA_METHODS: &str = "https://gsa.apple.com/auth";
    const _ENDPOINT_2FA_SMS_REQUEST: &str = "https://gsa.apple.com/auth/verify/phone";
    const _ENDPOINT_2FA_SMS_SUBMIT: &str = "https://gsa.apple.com/auth/verify/phone/securitycode";
    const _ENDPOINT_2FA_TD_REQUEST: &str = "https://gsa.apple.com/auth/verify/trusteddevice";
    const _ENDPOINT_2FA_TD_SUBMIT: &str = "https://gsa.apple.com/grandslam/GsService2/validate";

    // reports endpoints
    const ENDPOINT_REPORTS_FETCH: &str = "https://gateway.icloud.com/acsnservice/fetch";

    pub fn new(anisette_provider: RemoteAnisetteProvider) -> Self {
        Self {
            client: reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
            anisette_provider,
        }
    }

    pub async fn login(&mut self, username: &str, password: &str) -> Result<()> {
        let srp = SrpClient::<sha2_stable::Sha256>::new(&G_2048);

        let mut a = [0u8; 64];
        OsRng.try_fill_bytes(&mut a)?;

        let a_pub = srp.compute_public_ephemeral(&a);

        let r = self
            .gsa_request(&GsaRequest::ClientInit(GsaClientInit {
                a2k: a_pub,
                u: username.to_string(),
                ps: vec!["s2k".to_string(), "s2k_fo".to_string()],
                o: "init".to_string(),
            }))
            .await?;

        if r.get("Status")
            .unwrap()
            .as_dictionary()
            .unwrap()
            .get("ec")
            .unwrap()
            .as_signed_integer()
            .unwrap()
            != 0
        {
            anyhow::bail!("email verification failed");
        }

        let password_derived_key = Self::derive_key_from_password(
            password,
            r.get("s").unwrap().as_data().unwrap().try_into()?, // salt
            r.get("i")
                .unwrap()
                .as_unsigned_integer()
                .unwrap()
                .try_into()
                .unwrap(), // number of iterations,
            r.get("sp")
                .unwrap()
                .as_string()
                .unwrap()
                .try_into()
                .unwrap(),
        );

        let verifier = srp
            .process_reply(
                &a,
                username.as_bytes(),
                password_derived_key.as_slice(),
                r.get("s").unwrap().as_data().unwrap(),
                r.get("B").unwrap().as_data().unwrap(),
            )
            .unwrap();

        let client_proof = verifier.proof();

        let r = self
            .gsa_request(&GsaRequest::ClientComplete(GsaClientComplete {
                c: r.get("c").unwrap().as_string().unwrap().to_string(),
                m1: hex::encode(client_proof), // guess
                u: username.to_string(),
                o: "complete".to_string(),
            }))
            .await?;

        if r.get("Status")
            .unwrap()
            .as_dictionary()
            .unwrap()
            .get("ec")
            .unwrap()
            .as_signed_integer()
            .unwrap()
            != 0
        {
            anyhow::bail!("password verification failed");
        }

        verifier
            .verify_server(r.get("M2").unwrap().as_data().unwrap())
            .unwrap();

        let _session_key = verifier.key();

        // dbg!(&session_key);
        // dbg!(&r.get("spd").unwrap());

        todo!("plist::from_bytes(crypto.decrypt_spd_aes_cbc(session_key, r.get(\"spd\")))");

        // TODO: fully implement auth
        // TODO: implement 2FA
    }

    /// Fetch and decrypt reports for the given ephemeral secret keys from an accessory or owner
    /// device.
    pub async fn fetch_and_decrypt_reports(
        &mut self,
        keys: &[SecretKey],
    ) -> Result<Vec<AppleReportResponse<ReportPayloadAsReceived>>> {
        let ids_and_keys = keys.iter().map(|key| {
            (
                OfflineFindingPublicKey::from(&key.public_key()).hash(),
                key.clone(),
            )
        });

        let id_to_key = HashMap::<OfflineFindingPublicKeyId, SecretKey>::from_iter(ids_and_keys);
        let ids: Vec<OfflineFindingPublicKeyId> = id_to_key.keys().copied().collect();

        let raw_reports = self.fetch_raw_reports(ids.as_slice()).await.unwrap();

        let decrypted_reports: Result<Vec<AppleReportResponse<ReportPayloadAsReceived>>> =
            raw_reports
                .iter()
                .map(|raw_report| {
                    let id_in_report =
                        OfflineFindingPublicKeyId::try_from_base64(&raw_report.id).unwrap();
                    let ephemeral_private_key = id_to_key
                        .get(&id_in_report)
                        .expect("we shouldn't be receiving reports from IDs we didn't ask for");

                    raw_report.decrypt((*ephemeral_private_key).clone())
                })
                .collect();

        decrypted_reports
    }

    /// Fetch encrypted reports by ID.
    pub async fn fetch_raw_reports(
        &mut self,
        ids: &[OfflineFindingPublicKeyId],
    ) -> Result<Vec<AppleReportResponse<EncryptedReportPayload>>> {
        let headers = self.anisette_provider.get_headers(false).await;

        let now = Local::now().into();
        let fetch_request = ReportFetchRequest {
            search: vec![ReportSearch {
                // apple's supposed to return reports from the last 7
                // these timestamps are ignored by the server as of April 2025
                start_date: now - Duration::days(10),
                end_date: now,
                ids: ids.iter().map(|id| id.to_base64()).collect::<Vec<_>>(),
            }],
        };

        // TODO: actually implement login
        // TODO: expose the auth tokens at a higher level
        let basic_auth_username = env::var("APPLE_AUTH_DSID").unwrap();
        let basic_auth_password = env::var("APPLE_AUTH_SEARCH_PARTY_TOKEN").unwrap();

        let request = self
            .client
            .post(Self::ENDPOINT_REPORTS_FETCH)
            .headers(headers)
            .basic_auth(basic_auth_username, Some(basic_auth_password))
            .json(&fetch_request);

        #[derive(Deserialize, Debug)]
        struct Response {
            /// Results of the report search.
            results: Vec<AppleReportResponse<String>>,
        }

        let response = request.send().await?;
        let body: Response = response.json().await?;

        body.results
            .into_iter()
            .map(|response| response.try_into())
            .collect()
    }

    /// Perform a "grand slam" request.
    async fn gsa_request(&mut self, data: &GsaRequest) -> Result<plist::Dictionary> {
        let mut request_plist_request = plist::Dictionary::new();

        let cpd = self.anisette_provider.get_cpd().await?;
        request_plist_request.insert("cpd".to_string(), plist::Value::Dictionary(cpd));

        let data_as_plist_value = plist::to_value(data).unwrap();
        for (k, v) in data_as_plist_value.into_dictionary().unwrap() {
            request_plist_request.insert(k, v);
        }

        let mut request_plist_header = plist::Dictionary::new();
        request_plist_header.insert(
            "Version".to_string(),
            plist::Value::String("1.0.1".to_string()),
        );

        let mut request_plist_value = plist::Dictionary::new();
        request_plist_value.insert(
            "Header".to_string(),
            plist::Value::Dictionary(request_plist_header),
        );

        request_plist_value.insert(
            "Request".to_string(),
            plist::Value::Dictionary(request_plist_request),
        );

        let mut body_plist: Vec<u8> = vec![];
        plist::to_writer_binary(
            &mut body_plist,
            &plist::Value::Dictionary(request_plist_value),
        )?;

        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", "text/x-xml-plist".parse().unwrap());
        headers.insert("Accept", "*/*".parse().unwrap());
        headers.insert(
            "User-Agent",
            "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0".parse().unwrap(),
        );
        headers.insert(
            "X-MMe-Client-Info",
            RemoteAnisetteProvider::CLIENT.parse().unwrap(),
        );

        let resp = self
            .client
            .post(Self::ENDPOINT_GSA)
            .headers(headers)
            .body(body_plist)
            .send()
            .await?;

        #[derive(Deserialize, Debug)]
        struct Response {
            #[serde(rename = "Response")]
            response: plist::Dictionary,
        }

        let body: Response = plist::from_bytes(&resp.bytes().await?.slice(0..))?;

        Ok(body.response)
    }

    fn derive_key_from_password(
        password: &str,
        salt: &[u8; 32],
        iterations: u32,
        protocol: KdfProtocol,
    ) -> [u8; 32] {
        let hashed_password = sha2_stable::Sha256::digest(password.as_bytes());
        let password_bytes = match protocol {
            KdfProtocol::S2k => hashed_password.to_vec(),
            KdfProtocol::S2kFo => hex::encode(hashed_password).as_bytes().to_vec(),
        };

        pbkdf2::pbkdf2_hmac_array::<sha2_stable::Sha256, 32>(
            password_bytes.as_slice(),
            salt,
            iterations,
        )
    }

    // fn decrypt_spd_aes_cbc(session_key: &[u8], data: &[u8]) -> Vec<u8> {
    //     let mut mac = Hmac::<sha2_stable::Sha256>::new_from_slice(session_key);
    //     mac.update(b"extra data key:");
    //     let extra_data_key = mac.finalize();

    //     let mut mac = Hmac::<sha2_stable::Sha256>::new_from_slice(session_key);
    //     mac.update(b"extra data iv:");
    //     let extra_data_iv = mac.finalize()[..16];

    //     type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    //     let plaintext = Aes128CbcDec::new(&extra_data_key.into(), &extra_data_iv.into())
    //         .decrypt_padded_vec_mut::<aes::Pkcs7>(&data)
    //         .unwrap();

    //     plaintext
    // }
}

/// A result from a search for FindMy reports.
///
/// As fetched from Apple's servers, the payload would be a base64 string. However, there are
/// multiple valid ways of interpreting that payload, and it may be useful to be able to decrypt
/// that payload without losing the surrounding context of the report fetching result. Therefore,
/// we use the generic parameter `P` to be able to hold one of the multiple valid payload
/// representations.
#[derive(Serialize, Deserialize, Debug)]
pub struct AppleReportResponse<P: ReportPayload> {
    // TODO: see how it handles failures, and non-"found" reports
    /// Timestamp from when Apple's servers received the report.
    #[serde(
        rename = "datePublished",
        deserialize_with = "chrono::serde::ts_milliseconds::deserialize"
    )]
    date_published: DateTime<Utc>,
    /// Report payload.
    pub payload: P,
    /// Description of the report, often `"found"``.
    description: String,
    /// The ID of the accessory's public key.
    pub id: String,
    /// The status code of this result.
    #[serde(rename = "statusCode")]
    status_code: u8,
}

impl TryInto<AppleReportResponse<EncryptedReportPayload>> for AppleReportResponse<String> {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<AppleReportResponse<EncryptedReportPayload>, Self::Error> {
        let payload_bytes = b64.decode(&self.payload)?;
        let payload_deserialized =
            EncryptedReportPayload::deserialize(payload_bytes.as_slice().try_into().unwrap());

        match payload_deserialized {
            Ok(payload) => Ok(AppleReportResponse {
                date_published: self.date_published,
                payload,
                description: self.description.clone(),
                id: self.id.clone(),
                status_code: self.status_code,
            }),
            Err(_) => anyhow::bail!("failed to deserialize payload"),
        }
    }
}

impl AppleReportResponse<EncryptedReportPayload> {
    /// Attempt to decrypt the encrypted payload included in a report search result.
    pub fn decrypt(
        &self,
        private_key: SecretKey,
    ) -> Result<AppleReportResponse<ReportPayloadAsReceived>> {
        Ok(AppleReportResponse {
            date_published: self.date_published,
            payload: self.payload.decrypt(&private_key)?,
            description: self.description.clone(),
            id: self.id.clone(),
            status_code: self.status_code,
        })
    }
}

pub enum KdfProtocol {
    S2k,
    S2kFo,
}

impl TryFrom<&str> for KdfProtocol {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "s2k" => Ok(KdfProtocol::S2k),
            "s2k_fo" => Ok(KdfProtocol::S2kFo),
            _ => Err(()),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum GsaRequest {
    ClientInit(GsaClientInit),
    ClientComplete(GsaClientComplete),
}

#[derive(Serialize, Deserialize)]
pub struct GsaClientInit {
    #[serde(rename = "A2k")]
    a2k: Vec<u8>,
    u: String,
    ps: Vec<String>,
    o: String,
}

#[derive(Serialize, Deserialize)]
pub struct GsaClientComplete {
    c: String,
    #[serde(rename = "M1")]
    m1: String,
    u: String,
    o: String,
}

#[derive(Serialize, Deserialize)]
pub struct ReportFetchRequest {
    search: Vec<ReportSearch>,
}

/// Parameters for performing a search for reports.
#[derive(Serialize, Deserialize)]
pub struct ReportSearch {
    /// Lower bound on the timestamps of reports.
    #[serde(rename = "startDate", with = "chrono::serde::ts_milliseconds")]
    start_date: DateTime<Utc>,
    /// Upper bound on the timestamps of reports.
    #[serde(rename = "endDate", with = "chrono::serde::ts_milliseconds")]
    end_date: DateTime<Utc>,
    /// IDs of public keys to fetch reports for.
    ids: Vec<String>,
}
