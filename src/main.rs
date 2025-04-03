use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use clap::{Parser, Subcommand};

use offline_finding::{
    p224::SecretKey,
    protocol::{OfflineFindingPublicKey, ReportPayloadAsReceived},
    server::{AppleReportResponse, AppleReportsServer, RemoteAnisetteProvider},
};

#[derive(Parser)]
struct CliParser {
    /// Path to an anisette v3-compatible server.
    #[arg(long, default_value = "http://localhost:8000")]
    anisette_server: String,

    /// Command to execute.
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch raw reports from Apple's server without decrypting them.
    FetchRawReports {
        /// Base64-encoded 28-byte P224 private key.
        #[arg(long, group = "fetch-by")]
        private_key: Option<String>,
        /// Base64-encoded 28-byte P224 public key.
        #[arg(long, group = "fetch-by")]
        public_key: Option<String>,
        /// Base64-encoded SHA256 hash of a P224 public key.
        #[arg(long, group = "fetch-by")]
        hashed_public_key: Option<String>,
    },
    /// Fetch reports from Apple's server by private key and decrypt them.
    FetchReports { private_keys: Vec<String> },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli_args = CliParser::parse();
    let driver = AppleOfflineFinding::new(cli_args.anisette_server);

    match &cli_args.command {
        Command::FetchRawReports {
            private_key,
            public_key,
            hashed_public_key,
        } => {
            let hashed_of_public_key = match (private_key, public_key, hashed_public_key) {
                (Some(sk), _, _) => {
                    let decoded = b64.decode(sk)?;
                    let public_key = SecretKey::from_slice(&decoded).unwrap().public_key();
                    let of_public_key = OfflineFindingPublicKey::from(&public_key);

                    of_public_key.hash()
                }
                (_, Some(pk), _) => {
                    let decoded = b64.decode(pk)?;
                    let ofpk: &[u8; 28] = decoded.as_slice().try_into().unwrap();
                    let public_key =
                        offline_finding::p224::PublicKey::from(&OfflineFindingPublicKey(*ofpk));
                    let of_public_key = OfflineFindingPublicKey::from(&public_key);

                    of_public_key.hash()
                }
                (_, _, Some(hpk)) => b64.decode(hpk)?.as_slice().try_into().unwrap(),
                _ => unreachable!("clap shouldn't let this happen"),
            };

            let raw_reports = driver.fetch_raw_reports(hashed_of_public_key).await?;
            for raw_report in raw_reports {
                println!("{:?}", raw_report);
            }
        }
        Command::FetchReports { private_keys } => {
            if private_keys.len() > 255 {
                bail!("we don't support fetching more than 255 keys at once");
            }

            let decoded_private_keys: Vec<_> = private_keys
                .iter()
                .map(|sk| SecretKey::from_slice(b64.decode(sk).unwrap().as_slice()).unwrap())
                .collect();

            let decrypted_reports = driver.fetch_reports(decoded_private_keys).await?;
            for report in decrypted_reports {
                println!("{:?}", report);
            }
        }
    }

    Ok(())
}

struct AppleOfflineFinding {
    anisette_server: String,
}

impl AppleOfflineFinding {
    fn new(anisette_server_address: String) -> Self {
        Self {
            anisette_server: anisette_server_address,
        }
    }

    async fn fetch_raw_reports(
        &self,
        public_key_hash: [u8; 32],
    ) -> Result<Vec<AppleReportResponse<String>>> {
        let anisette_provider = RemoteAnisetteProvider::new(self.anisette_server.as_str());
        let mut server = AppleReportsServer::new(anisette_provider);
        // server.login("foo@example.com", "password").await.unwrap();

        let ids = [public_key_hash];

        server.fetch_raw_reports(&ids).await
    }

    async fn fetch_reports(
        &self,
        ephemeral_private_keys: Vec<SecretKey>,
    ) -> Result<Vec<AppleReportResponse<ReportPayloadAsReceived>>> {
        let anisette_provider = RemoteAnisetteProvider::new(self.anisette_server.as_str());
        let mut server = AppleReportsServer::new(anisette_provider);
        // server.login("foo@example.com", "password").await.unwrap();

        let key_hash_pairs: Vec<_> = ephemeral_private_keys
            .into_iter()
            .map(|epk| {
                (
                    epk.clone(),
                    OfflineFindingPublicKey::from(&epk.public_key()).hash(),
                )
            })
            .collect();

        server
            .fetch_and_decrypt_reports(key_hash_pairs.as_slice())
            .await
    }
}
