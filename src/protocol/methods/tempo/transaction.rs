//! Tempo transaction types for building and submitting transactions.
//!
//! This module provides types for building Tempo transactions. These are used
//! by the **server** when it needs to forward client-signed transactions to
//! a fee payer service or submit them directly.
//!
//! # Fee Sponsorship Flow
//!
//! When `fee_payer` is `true` in a ChargeRequest, the correct flow is:
//!
//! 1. **Client** builds a TempoTransaction (type 0x76) with fee payer placeholder,
//!    signs it, and returns it as a `transaction` credential (NOT broadcast)
//! 2. **Server** receives the signed transaction and forwards to the fee payer
//!    service via `eth_sendRawTransaction`
//! 3. **Fee payer** adds its signature and broadcasts the transaction
//!
//! **Important**: The client does NOT submit the transaction directly.
//!
//! # Types
//!
//! - [`TempoTransactionParams`]: Parameters for building a transaction request
//! - [`TempoSendTransactionRequest`]: JSON-RPC request for `tempo_sendTransaction`
//! - [`SubmissionMethod`]: Indicates which RPC method the server should use
//!
//! # Examples
//!
//! ## Server-side: Forward sponsored transaction
//!
//! ```
//! use mpay::protocol::intents::ChargeRequest;
//! use mpay::protocol::methods::tempo::TempoChargeExt;
//! use mpay::protocol::methods::tempo::transaction::SubmissionMethod;
//!
//! # let req = ChargeRequest {
//! #     amount: "1000000".into(),
//! #     currency: "0xToken".into(),
//! #     recipient: Some("0xRecipient".into()),
//! #     expires: None, description: None, external_id: None,
//! #     method_details: Some(serde_json::json!({"feePayer": true})),
//! # };
//! // Server receives a "transaction" credential with client-signed tx bytes
//! let method = SubmissionMethod::from_charge_request(&req);
//! if method == SubmissionMethod::TempoSendTransaction {
//!     // Forward to fee_payer_url (server responsibility, not client)
//!     let url = req.fee_payer_url();
//! }
//! ```

use serde::{Deserialize, Serialize};

use crate::protocol::intents::ChargeRequest;

use super::TempoChargeExt;

/// JSON-RPC method name for Tempo transactions.
pub const TEMPO_SEND_TRANSACTION_METHOD: &str = "tempo_sendTransaction";

/// JSON-RPC method name for standard Ethereum transactions.
pub const ETH_SEND_RAW_TRANSACTION_METHOD: &str = "eth_sendRawTransaction";

/// Parameters for a Tempo transaction.
///
/// This struct represents the transaction object passed to `tempo_sendTransaction`.
/// It supports Tempo-specific fields like `feePayer` for gas sponsorship.
///
/// # Examples
///
/// ```
/// use mpay::protocol::methods::tempo::transaction::TempoTransactionParams;
///
/// let params = TempoTransactionParams::new("0xSender", "0xRecipient")
///     .with_value("1000000")
///     .with_fee_payer(true)
///     .with_nonce_key("42");
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TempoTransactionParams {
    /// Transaction sender address
    pub from: String,

    /// Transaction recipient address
    pub to: String,

    /// Transaction value in wei (hex or decimal string)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,

    /// Transaction data (hex encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,

    /// Gas limit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<String>,

    /// Max fee per gas (EIP-1559)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<String>,

    /// Max priority fee per gas (EIP-1559)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<String>,

    /// Whether a fee payer should sponsor gas fees.
    /// When true, submit via `tempo_sendTransaction` to a fee payer service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<bool>,

    /// Token address for gas payment (TIP-20 fee payment).
    /// If not specified, uses the network's default fee token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_token: Option<String>,

    /// 2D nonce key for parallel transaction streams.
    /// If not specified, uses the default nonce stream (0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_key: Option<String>,

    /// Chain ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
}

impl TempoTransactionParams {
    /// Create new transaction params with required fields.
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            ..Default::default()
        }
    }

    /// Create transaction params from a ChargeRequest.
    ///
    /// Extracts Tempo-specific fields (fee_payer, nonce_key, fee_token, chain_id)
    /// from the ChargeRequest's method_details.
    pub fn from_charge_request(req: &ChargeRequest, from: impl Into<String>) -> Self {
        let to = req.recipient.clone().unwrap_or_default();

        let mut params = Self::new(from, to);

        if req.fee_payer() {
            params.fee_payer = Some(true);
        }

        let nonce_key = req.nonce_key();
        if !nonce_key.is_zero() {
            params.nonce_key = Some(nonce_key.to_string());
        }

        if let Some(fee_token) = req.fee_token() {
            params.fee_token = Some(fee_token);
        }

        if let Some(chain_id) = req.chain_id() {
            params.chain_id = Some(chain_id);
        }

        params
    }

    /// Set the transaction value.
    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    /// Set the transaction data.
    pub fn with_data(mut self, data: impl Into<String>) -> Self {
        self.data = Some(data.into());
        self
    }

    /// Set the gas limit.
    pub fn with_gas(mut self, gas: impl Into<String>) -> Self {
        self.gas = Some(gas.into());
        self
    }

    /// Enable fee sponsorship.
    pub fn with_fee_payer(mut self, fee_payer: bool) -> Self {
        self.fee_payer = Some(fee_payer);
        self
    }

    /// Set the fee token for TIP-20 gas payment.
    pub fn with_fee_token(mut self, fee_token: impl Into<String>) -> Self {
        self.fee_token = Some(fee_token.into());
        self
    }

    /// Set the 2D nonce key for parallel transactions.
    pub fn with_nonce_key(mut self, nonce_key: impl Into<String>) -> Self {
        self.nonce_key = Some(nonce_key.into());
        self
    }

    /// Set the chain ID.
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Check if this transaction requires fee sponsorship.
    pub fn requires_fee_payer(&self) -> bool {
        self.fee_payer.unwrap_or(false)
    }

    /// Get the appropriate RPC method for this transaction.
    ///
    /// Returns `tempo_sendTransaction` if fee sponsorship is requested,
    /// otherwise returns `eth_sendRawTransaction`.
    pub fn rpc_method(&self) -> &'static str {
        if self.requires_fee_payer() {
            TEMPO_SEND_TRANSACTION_METHOD
        } else {
            ETH_SEND_RAW_TRANSACTION_METHOD
        }
    }
}

/// JSON-RPC request for `tempo_sendTransaction`.
///
/// This is the complete request structure for submitting a Tempo transaction
/// via JSON-RPC.
///
/// # Examples
///
/// ```
/// use mpay::protocol::methods::tempo::transaction::{
///     TempoTransactionParams, TempoSendTransactionRequest,
/// };
///
/// let params = TempoTransactionParams::new("0xSender", "0xRecipient")
///     .with_fee_payer(true);
///
/// let request = TempoSendTransactionRequest::new(params);
/// let json = serde_json::to_string(&request).unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempoSendTransactionRequest {
    /// JSON-RPC version
    pub jsonrpc: String,

    /// RPC method name
    pub method: String,

    /// Transaction parameters
    pub params: Vec<TempoTransactionParams>,

    /// Request ID
    pub id: u64,
}

impl TempoSendTransactionRequest {
    /// Create a new tempo_sendTransaction request.
    pub fn new(params: TempoTransactionParams) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: TEMPO_SEND_TRANSACTION_METHOD.to_string(),
            params: vec![params],
            id: 1,
        }
    }

    /// Create a new request with a specific ID.
    pub fn with_id(params: TempoTransactionParams, id: u64) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: TEMPO_SEND_TRANSACTION_METHOD.to_string(),
            params: vec![params],
            id,
        }
    }
}

/// Submission method recommendation for a transaction.
///
/// Indicates which RPC method should be used to submit a transaction
/// based on its parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionMethod {
    /// Use `eth_sendRawTransaction` for standard transactions.
    EthSendRawTransaction,
    /// Use `tempo_sendTransaction` for sponsored or Tempo-specific transactions.
    TempoSendTransaction,
}

impl SubmissionMethod {
    /// Get the RPC method name.
    pub fn method_name(&self) -> &'static str {
        match self {
            Self::EthSendRawTransaction => ETH_SEND_RAW_TRANSACTION_METHOD,
            Self::TempoSendTransaction => TEMPO_SEND_TRANSACTION_METHOD,
        }
    }

    /// Determine submission method from a ChargeRequest.
    ///
    /// Returns `TempoSendTransaction` if fee sponsorship is requested,
    /// otherwise returns `EthSendRawTransaction`.
    pub fn from_charge_request(req: &ChargeRequest) -> Self {
        if req.fee_payer() {
            Self::TempoSendTransaction
        } else {
            Self::EthSendRawTransaction
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tempo_transaction_params_builder() {
        let params = TempoTransactionParams::new("0xSender", "0xRecipient")
            .with_value("1000000")
            .with_fee_payer(true)
            .with_nonce_key("42")
            .with_chain_id(88153);

        assert_eq!(params.from, "0xSender");
        assert_eq!(params.to, "0xRecipient");
        assert_eq!(params.value, Some("1000000".to_string()));
        assert!(params.requires_fee_payer());
        assert_eq!(params.nonce_key, Some("42".to_string()));
        assert_eq!(params.chain_id, Some(88153));
    }

    #[test]
    fn test_rpc_method_selection() {
        let sponsored = TempoTransactionParams::new("0xA", "0xB").with_fee_payer(true);
        assert_eq!(sponsored.rpc_method(), "tempo_sendTransaction");

        let standard = TempoTransactionParams::new("0xA", "0xB");
        assert_eq!(standard.rpc_method(), "eth_sendRawTransaction");
    }

    #[test]
    fn test_tempo_send_transaction_request_serialization() {
        let params = TempoTransactionParams::new("0xSender", "0xRecipient")
            .with_value("0x1000")
            .with_fee_payer(true);

        let request = TempoSendTransactionRequest::new(params);
        let json = serde_json::to_value(&request).unwrap();

        assert_eq!(json["jsonrpc"], "2.0");
        assert_eq!(json["method"], "tempo_sendTransaction");
        assert_eq!(json["params"][0]["from"], "0xSender");
        assert_eq!(json["params"][0]["to"], "0xRecipient");
        assert_eq!(json["params"][0]["value"], "0x1000");
        assert_eq!(json["params"][0]["feePayer"], true);
    }

    #[test]
    fn test_from_charge_request() {
        let req = ChargeRequest {
            amount: "1000000".to_string(),
            currency: "0xToken".to_string(),
            recipient: Some("0xRecipient".to_string()),
            expires: None,
            description: None,
            external_id: None,
            method_details: Some(serde_json::json!({
                "feePayer": true,
                "nonceKey": "42",
                "feeToken": "0xFeeToken",
                "chainId": 88153
            })),
        };

        let params = TempoTransactionParams::from_charge_request(&req, "0xSender");

        assert_eq!(params.from, "0xSender");
        assert_eq!(params.to, "0xRecipient");
        assert!(params.requires_fee_payer());
        assert_eq!(params.nonce_key, Some("42".to_string()));
        assert_eq!(params.fee_token, Some("0xFeeToken".to_string()));
        assert_eq!(params.chain_id, Some(88153));
    }

    #[test]
    fn test_submission_method() {
        let req_sponsored = ChargeRequest {
            amount: "1000".to_string(),
            currency: "0x".to_string(),
            recipient: None,
            expires: None,
            description: None,
            external_id: None,
            method_details: Some(serde_json::json!({"feePayer": true})),
        };
        assert_eq!(
            SubmissionMethod::from_charge_request(&req_sponsored),
            SubmissionMethod::TempoSendTransaction
        );

        let req_standard = ChargeRequest {
            amount: "1000".to_string(),
            currency: "0x".to_string(),
            recipient: None,
            expires: None,
            description: None,
            external_id: None,
            method_details: None,
        };
        assert_eq!(
            SubmissionMethod::from_charge_request(&req_standard),
            SubmissionMethod::EthSendRawTransaction
        );
    }

    #[test]
    fn test_skip_serializing_none_fields() {
        let params = TempoTransactionParams::new("0xA", "0xB");
        let json = serde_json::to_value(&params).unwrap();

        assert!(json.get("value").is_none());
        assert!(json.get("data").is_none());
        assert!(json.get("feePayer").is_none());
        assert!(json.get("nonceKey").is_none());
    }
}
