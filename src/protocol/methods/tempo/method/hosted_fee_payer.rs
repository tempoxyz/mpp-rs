//! Hosted (remote) fee payer: a JSON-RPC service that co-signs sponsored
//! transactions with `eth_fillTransaction`, as mppx's `feePayer: url` server
//! option. The server simulates and broadcasts the co-signed transaction
//! itself.

use alloy::eips::Encodable2718;
use alloy::primitives::{Address, Signature, TxKind, U256};
use alloy::providers::Provider;
use tempo_alloy::primitives::AASigned;
use tempo_alloy::TempoNetwork;

use crate::error::MppError;
use crate::protocol::traits::VerificationError;

use super::ChargeMethod;

/// A hosted fee-payer service, configured on the server.
///
/// The service sponsors a charge's transaction over JSON-RPC
/// `eth_fillTransaction` (with `feePayer: true`) and returns its
/// `feePayerSignature` and chosen `feeToken`. Only those two fields are taken
/// from its answer: every sender-committed field comes from the client's
/// signed envelope. The server then simulates the co-signed transaction and
/// broadcasts it through its own RPC.
///
/// Its token choice is unrestricted unless the server sets an explicit fee
/// token allowlist.
#[derive(Clone)]
pub struct RemoteFeePayer {
    url: String,
    headers: Vec<(String, String)>,
    client: Option<reqwest::Client>,
}

impl std::fmt::Debug for RemoteFeePayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Header values are usually credentials.
        f.debug_struct("RemoteFeePayer")
            .field("url", &self.url)
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl RemoteFeePayer {
    /// A hosted fee payer at the JSON-RPC endpoint `url`.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            headers: Vec::new(),
            client: None,
        }
    }

    /// Send `name: value` with every request, such as an `Authorization`
    /// header. `Content-Type` is always JSON and cannot be overridden.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Use `client` for fee-payer requests. It should not follow redirects,
    /// which would forward the configured headers to another host.
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = Some(client);
        self
    }

    /// The service's JSON-RPC endpoint.
    pub fn url(&self) -> &str {
        &self.url
    }

    pub(super) fn resolve(self) -> crate::error::Result<HostedFeePayer> {
        let url: reqwest::Url = self
            .url
            .parse()
            .map_err(|e| MppError::InvalidConfig(format!("invalid hosted fee payer URL: {e}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(MppError::InvalidConfig(
                "hosted fee payer URL must be http or https".into(),
            ));
        }
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in self.headers {
            let name: reqwest::header::HeaderName = name.parse().map_err(|e| {
                MppError::InvalidConfig(format!("invalid hosted fee payer header name: {e}"))
            })?;
            if name == reqwest::header::CONTENT_TYPE {
                continue;
            }
            let value: reqwest::header::HeaderValue = value.parse().map_err(|e| {
                MppError::InvalidConfig(format!("invalid hosted fee payer header value: {e}"))
            })?;
            headers.append(name, value);
        }
        let client = match self.client {
            Some(client) => client,
            None => reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(std::time::Duration::from_secs(10))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| {
                    MppError::InvalidConfig(format!("failed to build fee payer client: {e}"))
                })?,
        };
        Ok(HostedFeePayer {
            url,
            headers,
            client,
        })
    }
}

/// A validated [`RemoteFeePayer`].
#[derive(Clone)]
pub(super) struct HostedFeePayer {
    url: reqwest::Url,
    headers: reqwest::header::HeaderMap,
    client: reqwest::Client,
}

fn quantity(value: impl std::fmt::LowerHex) -> serde_json::Value {
    serde_json::Value::String(format!("{value:#x}"))
}

/// The `eth_fillTransaction` request asking a hosted fee payer to sponsor
/// `signed`: mppx's `hostedFeePayerRequest`, which leaves out what ox's
/// deserializer leaves unset (a zero gas limit, fee or call value, empty
/// calldata and absent validity bounds). The access list is always empty: the
/// sponsor reconstructs the transaction without it.
pub(super) fn hosted_fee_payer_request(signed: &AASigned, sender: Address) -> serde_json::Value {
    let tx = signed.tx();
    let calls: Vec<serde_json::Value> = tx
        .calls
        .iter()
        .map(|call| {
            let mut entry = serde_json::Map::new();
            if let TxKind::Call(to) = call.to {
                entry.insert("to".into(), serde_json::Value::String(format!("{to:#x}")));
            }
            if !call.input.is_empty() {
                entry.insert(
                    "data".into(),
                    serde_json::Value::String(alloy::hex::encode_prefixed(&call.input)),
                );
            }
            let value = if call.value.is_zero() {
                serde_json::Value::String("0x".into())
            } else {
                quantity(call.value)
            };
            entry.insert("value".into(), value);
            serde_json::Value::Object(entry)
        })
        .collect();

    let mut request = serde_json::Map::new();
    request.insert("calls".into(), serde_json::Value::Array(calls));
    request.insert("feePayer".into(), serde_json::Value::Bool(true));
    request.insert(
        "from".into(),
        serde_json::Value::String(format!("{sender:#x}")),
    );
    if tx.gas_limit != 0 {
        request.insert("gas".into(), quantity(tx.gas_limit));
    }
    if let Some(key_authorization) = &tx.key_authorization {
        request.insert(
            "keyAuthorization".into(),
            serde_json::to_value(key_authorization).unwrap_or(serde_json::Value::Null),
        );
    }
    if tx.max_fee_per_gas != 0 {
        request.insert("maxFeePerGas".into(), quantity(tx.max_fee_per_gas));
    }
    if tx.max_priority_fee_per_gas != 0 {
        request.insert(
            "maxPriorityFeePerGas".into(),
            quantity(tx.max_priority_fee_per_gas),
        );
    }
    request.insert("nonce".into(), quantity(tx.nonce));
    request.insert("nonceKey".into(), quantity(tx.nonce_key));
    request.insert("type".into(), serde_json::Value::String("0x76".into()));
    if let Some(valid_after) = tx.valid_after {
        request.insert("validAfter".into(), quantity(valid_after.get()));
    }
    if let Some(valid_before) = tx.valid_before {
        request.insert("validBefore".into(), quantity(valid_before.get()));
    }
    serde_json::Value::Object(request)
}

fn signature_word(value: Option<&serde_json::Value>) -> Option<U256> {
    match value? {
        serde_json::Value::String(text) => match text.strip_prefix("0x") {
            Some(hex) => U256::from_str_radix(hex, 16).ok(),
            None => U256::from_str_radix(text, 10).ok(),
        },
        serde_json::Value::Number(number) => number.as_u64().map(U256::from),
        _ => None,
    }
}

/// Parse a JSON-RPC signature object (`r`, `s` and `yParity`, or a legacy
/// `v` of 27 or 28).
fn parse_fee_payer_signature(value: &serde_json::Value) -> Option<Signature> {
    let r = signature_word(value.get("r"))?;
    let s = signature_word(value.get("s"))?;
    let parity = match signature_word(value.get("yParity")) {
        Some(parity) => parity,
        None => signature_word(value.get("v"))?.checked_sub(U256::from(27))?,
    };
    let parity = match u64::try_from(parity).ok()? {
        0 => false,
        1 => true,
        _ => return None,
    };
    if r.is_zero() || s.is_zero() {
        return None;
    }
    Some(Signature::new(r, s, parity))
}

fn invalid_sponsorship(reason: &str) -> VerificationError {
    VerificationError::internal(format!("Invalid transaction: {reason}"))
}

impl<P> ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Have the hosted fee payer co-sign a client's `0x78` envelope, as mppx's
    /// `fillHostedFeePayerTransaction`.
    ///
    /// Returns the co-signed `0x76` transaction and the sponsor address,
    /// recovered from its `feePayerSignature` over the sender's fields and
    /// its fee token, for the final simulation.
    pub(super) async fn fill_hosted_fee_payer_transaction(
        &self,
        hosted: &HostedFeePayer,
        tx_bytes: &[u8],
    ) -> Result<(Vec<u8>, Address), VerificationError> {
        let (signed, sender) = self.validate_fee_payer_transaction(tx_bytes, None)?;

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_fillTransaction",
            "params": [hosted_fee_payer_request(&signed, sender)],
        });
        let response = hosted
            .client
            .post(hosted.url.clone())
            .headers(hosted.headers.clone())
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                VerificationError::network_error(format!(
                    "hosted fee payer request failed: {}",
                    e.without_url()
                ))
            })?;
        let answer: serde_json::Value = response.json().await.map_err(|e| {
            VerificationError::network_error(format!(
                "hosted fee payer returned an invalid response: {}",
                e.without_url()
            ))
        })?;
        if let Some(error) = answer.get("error") {
            let message = error
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown error");
            return Err(VerificationError::internal(format!(
                "hosted fee payer failed to sponsor transaction: {message}"
            )));
        }

        let filled = answer.get("result").and_then(|result| result.get("tx"));
        let fee_payer_signature = filled
            .and_then(|tx| tx.get("feePayerSignature"))
            .filter(|signature| !signature.is_null())
            .ok_or_else(|| invalid_sponsorship("hosted fee payer failed to sponsor transaction"))?;
        let fee_token = filled
            .and_then(|tx| tx.get("feeToken"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid_sponsorship("hosted fee payer did not return a feeToken"))?;
        let fee_token: Address = fee_token
            .parse()
            .map_err(|_| invalid_sponsorship("fee-sponsored transaction feeToken is invalid"))?;
        if let Some(allowed) = &self.fee_payer_allowed_fee_tokens {
            if !allowed.contains(&fee_token) {
                return Err(invalid_sponsorship(
                    "fee-sponsored transaction feeToken is not allowed",
                ));
            }
        }
        let invalid_signature =
            || invalid_sponsorship("hosted fee payer returned an invalid feePayerSignature");
        let fee_payer_signature =
            parse_fee_payer_signature(fee_payer_signature).ok_or_else(invalid_signature)?;

        let (mut tx, client_signature, _) = signed.into_parts();
        tx.fee_token = Some(fee_token);
        tx.fee_payer_signature = None;
        let sponsor = fee_payer_signature
            .recover_address_from_prehash(&tx.fee_payer_signature_hash(sender))
            .map_err(|_| invalid_signature())?;
        tx.fee_payer_signature = Some(fee_payer_signature);
        Ok((tx.into_signed(client_signature).encoded_2718(), sponsor))
    }
}
