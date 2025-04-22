//! Command-line interface for fetching FindMy reports from Apple's servers.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use clap::{Args, Parser, Subcommand};

use offline_finding::{
    p224::SecretKey,
    protocol::{
        EncryptedReportPayload, OfflineFindingPublicKey, OfflineFindingPublicKeyId,
        ReportPayloadAsReceived,
    },
    server::{AppleReportResponse, AppleReportsServer, RemoteAnisetteProvider},
};

/// CLI to fetch FindMy reports.
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
        #[command(flatten)]
        /// Set of homogeneous key identifiers (e.g. public key IDs, private keys).
        identifiers: KeyIdentifiers,
    },
    /// Fetch reports from Apple's server by private key and decrypt them.
    FetchReports {
        /// Base64-encoded accessory private keys.
        private_keys: Vec<String>,
    },
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct KeyIdentifiers {
    // TODO: move the decoding of the identifiers into here. Having them all be `Vec<String>` is weird.
    /// Base64-encoded 28-byte P224 private keys.
    #[arg(
        long = "private-keys",
        aliases = ["private-key", "secret-keys", "secret-key"],
        short = 's',
        num_args = 1..=255
    )]
    private_keys: Option<Vec<String>>,

    /// Base64-encoded 28-byte P224 public key.
    #[arg(
        long = "public-keys",
        aliases = ["public-key"],
        short = 'p',
        num_args = 1..=255
    )]
    public_keys: Option<Vec<String>>,

    /// Base64-encoded SHA256 hash of a P224 public key.
    #[arg(
        long = "ids",
        aliases = ["hashed-public-keys", "hashed-public-keys"],
        short = 'i',
        num_args = 1..=255
    )]
    hashed_public_keys: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli_args = CliParser::parse();
    let driver = AppleOfflineFinding::new(cli_args.anisette_server);

    match &cli_args.command {
        Command::FetchRawReports { identifiers } => {
            let KeyIdentifiers {
                private_keys,
                public_keys,
                hashed_public_keys,
            } = identifiers;

            let hashed_of_public_keys: Vec<_> =
                match (private_keys, public_keys, hashed_public_keys) {
                    (Some(sks), _, _) => sks
                        .iter()
                        .map(|sk| {
                            let decoded = b64.decode(sk).unwrap();
                            let secret_key = SecretKey::from_slice(&decoded).unwrap();
                            let of_public_key = OfflineFindingPublicKey::from(&secret_key);

                            of_public_key.hash()
                        })
                        .collect(),
                    (_, Some(pks), _) => pks
                        .iter()
                        .map(|pk| {
                            let of_public_key =
                                OfflineFindingPublicKey::try_from_base64(pk).unwrap();

                            of_public_key.hash()
                        })
                        .collect(),
                    (_, _, Some(hpks)) => hpks
                        .iter()
                        .map(|hpk| OfflineFindingPublicKeyId::try_from_base64(hpk).unwrap())
                        .collect(),
                    _ => unreachable!("clap shouldn't let this happen"),
                };

            let raw_reports = driver.fetch_raw_reports(&hashed_of_public_keys).await?;
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

            let decrypted_reports = driver.fetch_reports(&decoded_private_keys).await?;
            for report in decrypted_reports {
                println!("{:?}", report);
            }
        }
    }

    Ok(())
}

/// Interface to Apple's FindMy report-fetching functionality.
struct AppleOfflineFinding {
    /// Address to an Anisette v3-compatible Anisette server.
    anisette_server: String,
}

impl AppleOfflineFinding {
    /// Construct a new interface to Apple's FindMy servers.
    fn new(anisette_server_address: String) -> Self {
        Self {
            anisette_server: anisette_server_address,
        }
    }

    /// Fetch encrypted reports for the given public key IDs.
    async fn fetch_raw_reports(
        &self,
        public_key_hashes: &[OfflineFindingPublicKeyId],
    ) -> Result<Vec<AppleReportResponse<EncryptedReportPayload>>> {
        let anisette_provider = RemoteAnisetteProvider::new(self.anisette_server.as_str());
        let mut server = AppleReportsServer::new(anisette_provider);
        // server.login("foo@example.com", "password").await.unwrap();

        server.fetch_raw_reports(public_key_hashes).await
    }

    /// Fetch and decrypt reports for the public keys corresponding to the given secret keys from the accessory or owner device.
    async fn fetch_reports(
        &self,
        ephemeral_private_keys: &[SecretKey],
    ) -> Result<Vec<AppleReportResponse<ReportPayloadAsReceived>>> {
        let anisette_provider = RemoteAnisetteProvider::new(self.anisette_server.as_str());
        let mut server = AppleReportsServer::new(anisette_provider);
        // server.login("foo@example.com", "password").await.unwrap();

        server
            .fetch_and_decrypt_reports(ephemeral_private_keys)
            .await
    }
}
