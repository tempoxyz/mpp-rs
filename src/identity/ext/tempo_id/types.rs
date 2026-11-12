//! Tempo ID users and keys.

use std::collections::HashMap;
use std::fmt;

use alloy::primitives::Address;

/// The screening state of a Tempo Account: only `clear` may pay without limits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ComplianceState {
    /// Cleared to pay.
    Clear,
    /// May only move funds out.
    ExitOnly,
    /// Blocked.
    Blocked,
    /// Screening has not finished.
    Pending,
    /// A state this version does not know, as Tempo ID sent it.
    Other(String),
}

impl ComplianceState {
    pub(crate) fn parse(value: &str) -> Self {
        match value {
            "clear" => Self::Clear,
            "exit_only" => Self::ExitOnly,
            "blocked" => Self::Blocked,
            "pending" => Self::Pending,
            other => Self::Other(other.to_owned()),
        }
    }

    /// The state as Tempo ID names it.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Clear => "clear",
            Self::ExitOnly => "exit_only",
            Self::Blocked => "blocked",
            Self::Pending => "pending",
            Self::Other(other) => other,
        }
    }
}

/// A Tempo ID user, as a verified access token (and, when sent, ID token) names them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The Tempo ID user ID: stable across every app on Tempo ID.
    pub user_id: String,
    /// The app the user signed in to.
    pub client_id: String,
    /// The Tempo Accounts the token grants to the app on the configured chain.
    pub accounts: Vec<Address>,
    /// The screening state of each account in the app's realms. Empty for an unregistered app.
    pub compliance: HashMap<Address, ComplianceState>,
    /// The user's email address, lowercased, from the ID token. Absent without
    /// one, or without the `email` scope.
    pub email: Option<String>,
    /// Whether Tempo ID verified the email address.
    pub email_verified: Option<bool>,
}

/// A verified Tempo ID user and the Tempo Account that paid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payer {
    /// The verified user.
    pub caller: Caller,
    /// The account that paid. Absent when the check ran without a Credential.
    pub account: Option<Address>,
}

impl std::ops::Deref for Payer {
    type Target = Caller;

    fn deref(&self) -> &Caller {
        &self.caller
    }
}

/// An ES256 DPoP key (RFC 9449), such as the Tempo ID SDK's session key.
#[derive(Clone)]
pub struct DpopKey {
    pub(crate) signing_key: p256::ecdsa::SigningKey,
}

impl DpopKey {
    /// A DPoP key from its P-256 signing key.
    pub fn new(signing_key: p256::ecdsa::SigningKey) -> Self {
        Self { signing_key }
    }

    /// The public key's `x` and `y` coordinates, base64url-encoded, as its JWK carries them.
    pub fn public_coordinates(&self) -> (String, String) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let point = self.signing_key.verifying_key().to_encoded_point(false);
        let x = point
            .x()
            .map(|x| URL_SAFE_NO_PAD.encode(x))
            .unwrap_or_default();
        let y = point
            .y()
            .map(|y| URL_SAFE_NO_PAD.encode(y))
            .unwrap_or_default();
        (x, y)
    }

    /// The RFC 7638 thumbprint of the public key, as a DPoP-bound token's `cnf.jkt` names it.
    pub fn thumbprint(&self) -> String {
        let (x, y) = self.public_coordinates();
        super::jwt::thumbprint("P-256", "EC", &x, &y)
    }
}

impl fmt::Debug for DpopKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopKey")
            .field("thumbprint", &self.thumbprint())
            .finish_non_exhaustive()
    }
}
