//! Tempo Wallet state shared by native MPP command-line clients.

use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use alloy::primitives::Address;
use alloy::signers::Signer;
use serde::Deserialize;

use super::signing::{P256Jwk, TempoP256Signer};

/// A Tempo Wallet account and its active P-256 access key.
#[derive(Debug)]
pub struct TempoWallet {
    /// Root Tempo account controlled by the access key.
    pub account: Address,
    /// On-chain address of the active access key.
    pub access_key: Address,
    /// Chain selected by Tempo Wallet.
    pub chain_id: u64,
    /// Native signer reconstructed from the persisted WebCrypto JWK.
    pub signer: TempoP256Signer,
}

/// Errors returned while loading Tempo Wallet state.
#[derive(Debug, thiserror::Error)]
pub enum TempoWalletError {
    /// The platform did not expose a home directory.
    #[error("home directory is unavailable")]
    HomeUnavailable,
    /// The wallet file could not be read.
    #[error("failed to read Tempo Wallet state at {path}: {source}")]
    Read {
        /// Wallet path.
        path: PathBuf,
        /// Filesystem error.
        source: std::io::Error,
    },
    /// The wallet file was not valid JSON state.
    #[error("invalid Tempo Wallet state at {path}: {source}")]
    Decode {
        /// Wallet path.
        path: PathBuf,
        /// JSON error.
        source: serde_json::Error,
    },
    /// The active account selector was missing or invalid.
    #[error("Tempo Wallet active account is missing or invalid")]
    ActiveAccount,
    /// No matching access key was available for the active account and chain.
    #[error("Tempo Wallet has no access key for active chain {0}")]
    MissingAccessKey(u64),
    /// The stored key is not an extractable WebCrypto P-256 JWK.
    #[error("Tempo Wallet access key must be an extractable P-256 JWK")]
    UnsupportedAccessKey,
    /// The persisted JWK could not be reconstructed.
    #[error("failed to load Tempo Wallet access key: {0}")]
    InvalidAccessKey(#[from] super::signing::P256SignerError),
    /// The JWK-derived address did not match the stored access-key address.
    #[error("Tempo Wallet access-key address does not match its persisted JWK")]
    AccessKeyAddressMismatch,
}

impl TempoWallet {
    /// Load the active account and access key from a Tempo Wallet store.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, TempoWalletError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|source| TempoWalletError::Read {
            path: path.to_owned(),
            source,
        })?;
        let file: TempoWalletFile =
            serde_json::from_slice(&bytes).map_err(|source| TempoWalletError::Decode {
                path: path.to_owned(),
                source,
            })?;
        let state = file.store.state;
        let account = active_account(&state)?;
        let access_key = state
            .access_keys
            .into_iter()
            .find(|key| key.chain_id == state.chain_id && key.access == account)
            .ok_or(TempoWalletError::MissingAccessKey(state.chain_id))?;
        if access_key.key_type != "p256" || access_key.handle.kind != "webcrypto-p256" {
            return Err(TempoWalletError::UnsupportedAccessKey);
        }
        let signer = TempoP256Signer::from_webcrypto_jwk(&access_key.handle.jwk)?;
        if signer.address() != access_key.address {
            return Err(TempoWalletError::AccessKeyAddressMismatch);
        }
        Ok(Self {
            account,
            access_key: access_key.address,
            chain_id: state.chain_id,
            signer,
        })
    }

    /// Load `~/.tempo/wallet/store.json`.
    pub fn load_default() -> Result<Self, TempoWalletError> {
        Self::load(default_wallet_store_path()?)
    }
}

/// Return the wallet path shared by Tempo command-line applications.
pub fn default_wallet_store_path() -> Result<PathBuf, TempoWalletError> {
    dirs::home_dir()
        .map(|home| home.join(".tempo").join("wallet").join("store.json"))
        .ok_or(TempoWalletError::HomeUnavailable)
}

#[derive(Deserialize)]
struct TempoWalletFile {
    #[serde(rename = "tempo-cli.store")]
    store: TempoWalletEnvelope,
}

#[derive(Deserialize)]
struct TempoWalletEnvelope {
    state: TempoWalletState,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TempoWalletState {
    active_account: serde_json::Value,
    chain_id: u64,
    accounts: Vec<TempoWalletAccount>,
    access_keys: Vec<TempoAccessKey>,
}

#[derive(Deserialize)]
struct TempoWalletAccount {
    address: Address,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TempoAccessKey {
    address: Address,
    access: Address,
    chain_id: u64,
    key_type: String,
    handle: TempoAccessKeyHandle,
}

#[derive(Deserialize)]
struct TempoAccessKeyHandle {
    kind: String,
    jwk: P256Jwk,
}

fn active_account(state: &TempoWalletState) -> Result<Address, TempoWalletError> {
    if let Some(index) = state.active_account.as_u64() {
        return usize::try_from(index)
            .ok()
            .and_then(|index| state.accounts.get(index))
            .map(|account| account.address)
            .ok_or(TempoWalletError::ActiveAccount);
    }
    if let Some(address) = state.active_account.as_str() {
        let address = Address::from_str(address).map_err(|_| TempoWalletError::ActiveAccount)?;
        if state
            .accounts
            .iter()
            .any(|account| account.address == address)
        {
            return Ok(address);
        }
    }
    Err(TempoWalletError::ActiveAccount)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_active_account_by_index_or_address() {
        let address: Address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
            .parse()
            .unwrap();
        let state = TempoWalletState {
            active_account: serde_json::json!(0),
            chain_id: 4217,
            accounts: vec![TempoWalletAccount { address }],
            access_keys: vec![],
        };
        assert_eq!(active_account(&state).unwrap(), address);

        let state = TempoWalletState {
            active_account: serde_json::json!(address.to_string()),
            ..state
        };
        assert_eq!(active_account(&state).unwrap(), address);
    }

    #[test]
    fn loads_accounts_sdk_access_key() {
        let path =
            std::env::temp_dir().join(format!("mpp-rs-tempo-wallet-{}.json", std::process::id()));
        let json = r#"{
          "tempo-cli.store": {
            "state": {
              "activeAccount": 0,
              "chainId": 4217,
              "accounts": [{"address":"0x1111111111111111111111111111111111111111"}],
              "accessKeys": [{
                "address":"0xf0159a522607cd6ab1097204c9fafb7bbe6afb6c",
                "access":"0x1111111111111111111111111111111111111111",
                "chainId":4217,
                "keyType":"p256",
                "handle":{"kind":"webcrypto-p256","jwk":{
                  "kty":"EC","crv":"P-256",
                  "x":"OtOGGpViE5JRa7WT7wVYPtLlhm9ctiYKMBcjf9ibkK8",
                  "y":"0JYcfjcHWmeRo5xh9WKVsCttJlZ7YV5gqkHuHI6DOI0",
                  "d":"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"
                }}
              }]
            }
          }
        }"#;
        fs::write(&path, json).unwrap();
        let wallet = TempoWallet::load(&path).unwrap();
        fs::remove_file(path).unwrap();

        assert_eq!(
            wallet.account,
            "0x1111111111111111111111111111111111111111"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            wallet.access_key,
            "0xf0159a522607cd6ab1097204c9fafb7bbe6afb6c"
                .parse::<Address>()
                .unwrap()
        );
    }
}
