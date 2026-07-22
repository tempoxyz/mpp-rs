//! Tempo Wallet state shared by native MPP command-line clients.

use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use alloy::primitives::{Address, Bytes, Signature, B256, U256};
use alloy::signers::Signer;
use serde::{de::Error as _, Deserialize, Deserializer};
use tempo_primitives::transaction::{
    tt_signature::{P256SignatureWithPreHash, WebAuthnSignature},
    KeyAuthorization, PrimitiveSignature, SignatureType, SignedKeyAuthorization, TokenLimit,
};

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
    /// Signed authorization attached while the active access key is not yet on-chain.
    pub key_authorization: Option<Box<SignedKeyAuthorization>>,
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
            key_authorization: access_key.key_authorization.map(Box::new),
        })
    }

    /// Load `~/.tempo/wallet/store.json`.
    pub fn load_default() -> Result<Self, TempoWalletError> {
        Self::load(default_wallet_store_path()?)
    }
}

/// Return the wallet path shared by Tempo command-line applications.
pub fn default_wallet_store_path() -> Result<PathBuf, TempoWalletError> {
    super::default_wallet_directory()
        .map(|directory| directory.join("store.json"))
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
    #[serde(default, deserialize_with = "deserialize_key_authorization")]
    key_authorization: Option<SignedKeyAuthorization>,
}

#[derive(Deserialize)]
struct TempoAccessKeyHandle {
    kind: String,
    jwk: P256Jwk,
}

fn deserialize_key_authorization<'de, D>(
    deserializer: D,
) -> Result<Option<SignedKeyAuthorization>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    value
        .as_ref()
        .map(parse_key_authorization)
        .transpose()
        .map_err(D::Error::custom)
}

fn parse_key_authorization(value: &serde_json::Value) -> Result<SignedKeyAuthorization, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "Tempo Wallet keyAuthorization must be an object".to_owned())?;
    if object.contains_key("scopes") {
        return Err("Tempo Wallet keyAuthorization scopes are not yet supported".to_owned());
    }
    let key_type = match string_field(object, "type")? {
        "secp256k1" => SignatureType::Secp256k1,
        "p256" => SignatureType::P256,
        "webAuthn" => SignatureType::WebAuthn,
        value => return Err(format!("unsupported Tempo Wallet key type {value}")),
    };
    let key_id = string_field(object, "address")?
        .parse()
        .map_err(|error| format!("invalid Tempo Wallet access-key address: {error}"))?;
    let chain_id = tagged_u256(value_field(object, "chainId")?, "chainId")?
        .try_into()
        .map_err(|_| "Tempo Wallet keyAuthorization chainId exceeds u64".to_owned())?;
    let expiry = object
        .get("expiry")
        .filter(|value| !value.is_null())
        .map(|value| tagged_u256(value, "expiry"))
        .transpose()?
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| "Tempo Wallet keyAuthorization expiry exceeds u64".to_owned())
        })
        .transpose()?
        .and_then(std::num::NonZeroU64::new);
    let limits = object
        .get("limits")
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| "Tempo Wallet keyAuthorization limits must be an array".to_owned())?
                .iter()
                .map(parse_token_limit)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    let witness = object
        .get("witness")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| "Tempo Wallet keyAuthorization witness must be hex".to_owned())?
                .parse()
                .map_err(|error| format!("invalid Tempo Wallet keyAuthorization witness: {error}"))
        })
        .transpose()?;
    let account = object
        .get("account")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| {
                    "Tempo Wallet keyAuthorization account must be an address".to_owned()
                })?
                .parse()
                .map_err(|error| format!("invalid Tempo Wallet keyAuthorization account: {error}"))
        })
        .transpose()?;
    let authorization = KeyAuthorization {
        chain_id,
        key_type,
        key_id,
        expiry,
        limits,
        allowed_calls: None,
        witness,
        is_admin: object
            .get("isAdmin")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        account,
    };
    let signature = parse_primitive_signature(value_field(object, "signature")?)?;
    Ok(SignedKeyAuthorization::new(authorization, signature))
}

fn parse_token_limit(value: &serde_json::Value) -> Result<TokenLimit, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "Tempo Wallet token limit must be an object".to_owned())?;
    Ok(TokenLimit {
        token: string_field(object, "token")?
            .parse()
            .map_err(|error| format!("invalid Tempo Wallet token-limit address: {error}"))?,
        limit: tagged_u256(value_field(object, "limit")?, "limit")?,
        period: object
            .get("period")
            .map(|value| tagged_u256(value, "period"))
            .transpose()?
            .map(u64::try_from)
            .transpose()
            .map_err(|_| "Tempo Wallet token-limit period exceeds u64".to_owned())?
            .unwrap_or_default(),
    })
}

fn parse_primitive_signature(value: &serde_json::Value) -> Result<PrimitiveSignature, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "Tempo Wallet keyAuthorization signature must be an object".to_owned())?;
    match string_field(object, "type")? {
        "secp256k1" => {
            let signature = object
                .get("signature")
                .and_then(serde_json::Value::as_object)
                .unwrap_or(object);
            Ok(PrimitiveSignature::Secp256k1(Signature::new(
                tagged_u256(value_field(signature, "r")?, "signature.r")?,
                tagged_u256(value_field(signature, "s")?, "signature.s")?,
                tagged_u256(value_field(signature, "yParity")?, "signature.yParity")? != U256::ZERO,
            )))
        }
        "p256" => {
            let (r, s, x, y) = signature_components(object)?;
            Ok(PrimitiveSignature::P256(P256SignatureWithPreHash {
                r,
                s,
                pub_key_x: x,
                pub_key_y: y,
                pre_hash: object
                    .get("prehash")
                    .or_else(|| object.get("preHash"))
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            }))
        }
        "webAuthn" => {
            let (r, s, x, y) = signature_components(object)?;
            let metadata = value_field(object, "metadata")?
                .as_object()
                .ok_or_else(|| "Tempo Wallet WebAuthn metadata must be an object".to_owned())?;
            let mut webauthn_data = hex_bytes(string_field(metadata, "authenticatorData")?)?;
            webauthn_data.extend_from_slice(string_field(metadata, "clientDataJSON")?.as_bytes());
            Ok(PrimitiveSignature::WebAuthn(WebAuthnSignature {
                r,
                s,
                pub_key_x: x,
                pub_key_y: y,
                webauthn_data: Bytes::from(webauthn_data),
            }))
        }
        value => Err(format!(
            "unsupported Tempo Wallet key-authorization signature type {value}"
        )),
    }
}

fn signature_components(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(B256, B256, B256, B256), String> {
    let signature = value_field(object, "signature")?
        .as_object()
        .ok_or_else(|| "Tempo Wallet signature coordinates must be an object".to_owned())?;
    let public_key = value_field(object, "publicKey")?
        .as_object()
        .ok_or_else(|| "Tempo Wallet public key must be an object".to_owned())?;
    Ok((
        tagged_b256(value_field(signature, "r")?, "signature.r")?,
        tagged_b256(value_field(signature, "s")?, "signature.s")?,
        tagged_b256(value_field(public_key, "x")?, "publicKey.x")?,
        tagged_b256(value_field(public_key, "y")?, "publicKey.y")?,
    ))
}

fn tagged_b256(value: &serde_json::Value, field: &str) -> Result<B256, String> {
    Ok(B256::from(tagged_u256(value, field)?.to_be_bytes::<32>()))
}

fn tagged_u256(value: &serde_json::Value, field: &str) -> Result<U256, String> {
    if let Some(value) = value.as_u64() {
        return Ok(U256::from(value));
    }
    let value = value
        .as_str()
        .ok_or_else(|| format!("Tempo Wallet {field} must be an integer"))?;
    let value = value.strip_suffix("#__bigint").unwrap_or(value);
    if let Some(value) = value.strip_prefix("0x") {
        U256::from_str_radix(value, 16)
    } else {
        U256::from_str_radix(value, 10)
    }
    .map_err(|error| format!("invalid Tempo Wallet {field}: {error}"))
}

fn value_field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a serde_json::Value, String> {
    object
        .get(field)
        .ok_or_else(|| format!("Tempo Wallet keyAuthorization is missing {field}"))
}

fn string_field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a str, String> {
    value_field(object, field)?
        .as_str()
        .ok_or_else(|| format!("Tempo Wallet keyAuthorization {field} must be a string"))
}

fn hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    alloy::hex::decode(value).map_err(|error| format!("invalid Tempo Wallet hex bytes: {error}"))
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
                }},
                "keyAuthorization": {
                  "address":"0xf0159a522607cd6ab1097204c9fafb7bbe6afb6c",
                  "chainId":"4217#__bigint",
                  "expiry":4102444800,
                  "limits":[{
                    "token":"0x20c0000000000000000000000000000000000000",
                    "limit":"100000000#__bigint"
                  }],
                  "type":"p256",
                  "signature":{
                    "metadata":{"authenticatorData":"0x010203","clientDataJSON":"{}"},
                    "publicKey":{"prefix":4,"x":"3#__bigint","y":"4#__bigint"},
                    "signature":{"r":"1#__bigint","s":"2#__bigint"},
                    "type":"webAuthn"
                  }
                }
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
        let authorization = wallet.key_authorization.unwrap();
        assert_eq!(authorization.chain_id, 4217);
        assert_eq!(authorization.key_id, wallet.access_key);
        assert_eq!(
            authorization.limits.as_ref().unwrap()[0].limit,
            U256::from(100_000_000)
        );
        let PrimitiveSignature::WebAuthn(signature) = &authorization.signature else {
            panic!("expected WebAuthn root authorization")
        };
        assert_eq!(signature.webauthn_data.as_ref(), b"\x01\x02\x03{}");
    }
}
