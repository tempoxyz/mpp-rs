//! Tempo CLI keystore provider.
//!
//! Delegates signing to the `tempo` CLI's `wallet sign` subcommand, reading
//! keys from `~/.tempo/wallet/keys.toml`. This avoids embedding private keys
//! in your application — the CLI handles key resolution, keychain signing
//! modes, and key authorization provisioning.
//!
//! # Usage
//!
//! ```ignore
//! use mpp::client::{TempoCliProvider, Fetch};
//!
//! let provider = TempoCliProvider::new();
//! let resp = client.get(url).send_with_payment(&provider).await?;
//! ```
//!
//! The provider pipes the WWW-Authenticate challenge to `tempo wallet sign`
//! via stdin and parses the resulting Authorization header from JSON output.

use std::io::Write;
use std::process::Command;

use crate::client::PaymentProvider;
use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential};

/// JSON output from `tempo wallet sign --output json`.
#[derive(serde::Deserialize)]
struct SignOutput {
    authorization: String,
}

/// A payment provider that delegates signing to the `tempo` CLI.
///
/// Reads the wallet keystore (`~/.tempo/wallet/keys.toml`) via the CLI
/// and delegates transaction signing to `tempo wallet sign`. This means:
///
/// - No private keys in your application's memory
/// - Automatic keychain (access key) signing mode resolution
/// - Key authorization provisioning handled by the CLI
///
/// # Requirements
///
/// - The `tempo` binary must be in `$PATH` (or set via [`TempoCliProvider::with_binary`])
/// - A wallet must be configured via `tempo wallet login`
///
/// # Examples
///
/// ```ignore
/// use mpp::client::TempoCliProvider;
///
/// // Default: uses `tempo` binary from $PATH
/// let provider = TempoCliProvider::new();
///
/// // Custom binary path
/// let provider = TempoCliProvider::new().with_binary("/usr/local/bin/tempo");
/// ```
#[derive(Clone, Debug)]
pub struct TempoCliProvider {
    /// Path to the `tempo` binary.
    binary: String,
    /// Optional `--network` pin passed to `tempo wallet sign`.
    network: Option<String>,
}

impl TempoCliProvider {
    /// Create a new CLI provider using the default `tempo` binary.
    pub fn new() -> Self {
        Self {
            binary: "tempo".to_string(),
            network: None,
        }
    }

    /// Override the path to the `tempo` binary.
    pub fn with_binary(mut self, binary: impl Into<String>) -> Self {
        self.binary = binary.into();
        self
    }

    /// Pin signing to a specific network (e.g., `"tempo"` or `"tempo-moderato"`).
    ///
    /// Passed as `--network <value>` to `tempo wallet sign`.
    pub fn with_network(mut self, network: impl Into<String>) -> Self {
        self.network = Some(network.into());
        self
    }

    /// Run `tempo wallet sign` and return the parsed credential.
    ///
    /// The challenge is piped via stdin to avoid exposing it in process
    /// arguments (visible to `ps`).
    fn sign_challenge(&self, www_authenticate: &str) -> Result<PaymentCredential, MppError> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("wallet").arg("sign").arg("--output").arg("json");

        if let Some(ref network) = self.network {
            cmd.arg("--network").arg(network);
        }

        // Pipe the challenge via stdin instead of argv
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                MppError::InvalidConfig(format!(
                    "tempo CLI not found at '{}'. Install it or set a custom path \
                     with TempoCliProvider::with_binary()",
                    self.binary
                ))
            } else {
                MppError::Http(format!("failed to run tempo CLI: {}", e))
            }
        })?;

        // Write the challenge to stdin
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(www_authenticate.as_bytes());
            // stdin is dropped here, closing the pipe
        }

        let output = child
            .wait_with_output()
            .map_err(|e| MppError::Http(format!("failed to wait for tempo CLI: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Cap stderr to avoid leaking sensitive data
            let capped: &str = if stderr.len() > 512 {
                &stderr[..512]
            } else {
                &stderr
            };
            return Err(MppError::InvalidConfig(format!(
                "tempo wallet sign failed (exit {}): {}",
                output.status.code().unwrap_or(-1),
                capped.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let sign_output: SignOutput = serde_json::from_str(stdout.trim()).map_err(|e| {
            MppError::InvalidConfig(format!("failed to parse tempo CLI output: {}", e))
        })?;

        crate::parse_authorization(&sign_output.authorization)
    }
}

impl Default for TempoCliProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PaymentProvider for TempoCliProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        method == "tempo" && intent == "charge"
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        let www_authenticate = crate::format_www_authenticate(challenge)?;
        self.sign_challenge(&www_authenticate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_defaults() {
        let provider = TempoCliProvider::new();
        assert_eq!(provider.binary, "tempo");
        assert!(provider.network.is_none());
    }

    #[test]
    fn test_with_binary() {
        let provider = TempoCliProvider::new().with_binary("/usr/local/bin/tempo");
        assert_eq!(provider.binary, "/usr/local/bin/tempo");
    }

    #[test]
    fn test_with_network() {
        let provider = TempoCliProvider::new().with_network("tempo-moderato");
        assert_eq!(provider.network.as_deref(), Some("tempo-moderato"));
    }

    #[test]
    fn test_default_impl() {
        let provider = TempoCliProvider::default();
        assert_eq!(provider.binary, "tempo");
    }

    #[test]
    fn test_supports() {
        let provider = TempoCliProvider::new();
        assert!(provider.supports("tempo", "charge"));
        assert!(!provider.supports("tempo", "session"));
        assert!(!provider.supports("stripe", "charge"));
        assert!(!provider.supports("TEMPO", "charge"));
    }

    #[test]
    fn test_clone() {
        let provider = TempoCliProvider::new()
            .with_binary("/custom/tempo")
            .with_network("tempo");
        let cloned = provider.clone();
        assert_eq!(cloned.binary, "/custom/tempo");
        assert_eq!(cloned.network.as_deref(), Some("tempo"));
    }

    #[test]
    fn test_sign_challenge_binary_not_found() {
        let provider = TempoCliProvider::new().with_binary("/nonexistent/tempo-does-not-exist");
        let result = provider.sign_challenge("Payment id=\"test\"");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"), "expected 'not found' in: {err}");
    }
}
