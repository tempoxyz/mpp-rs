//! ERC-8004 agents on the client: a prover, as mppx's `Erc8004.Client.prover`.

use std::fmt;
use std::sync::Arc;

use alloy::primitives::{Address, U256};
use alloy::signers::Signer;
use reqwest::header::HeaderValue;
use reqwest::Request;

use super::constants::{CHAIN_ID, IDENTITY_REGISTRY, ID_HEADER, SIGNATURE_HEADER};
use super::{message, AgentRef};
use crate::identity::client::{ProveContext, Prover, ProverError, Scope};
use crate::identity::BoxFuture;

/// ERC-8004 prover options, as mppx's `Erc8004.Client.prover` config.
#[derive(Clone)]
pub struct ProverConfig {
    signer: Arc<dyn Signer + Send + Sync>,
    agent_id: U256,
    scope: Scope,
    chain_id: u64,
    registry: Address,
}

impl fmt::Debug for ProverConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProverConfig")
            .field("agent_id", &self.agent_id)
            .field("scope", &self.scope)
            .field("chain_id", &self.chain_id)
            .field("registry", &self.registry)
            .finish_non_exhaustive()
    }
}

impl ProverConfig {
    /// Signs requests to the origins in `scope` as agent `agent_id` of the
    /// Identity Registry on Tempo mainnet, with `signer`: the agent's wallet,
    /// which also pays.
    pub fn new<S>(signer: S, agent_id: U256, scope: Scope) -> Self
    where
        S: Signer + Send + Sync + 'static,
    {
        Self {
            signer: Arc::new(signer),
            agent_id,
            scope,
            chain_id: CHAIN_ID,
            registry: IDENTITY_REGISTRY,
        }
    }

    /// The registry's chain. Default: 4217 (Tempo mainnet).
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// The Identity Registry. Default: `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`.
    pub fn registry(mut self, registry: Address) -> Self {
        self.registry = registry;
        self
    }
}

/// Creates a prover that signs each request as an ERC-8004 agent, with the agent's wallet.
pub fn prover(config: ProverConfig) -> Erc8004Prover {
    let id = AgentRef {
        chain_id: config.chain_id,
        registry: config.registry,
        agent_id: config.agent_id,
    }
    .format();
    Erc8004Prover { config, id }
}

/// The prover [`prover`] returns.
#[derive(Debug, Clone)]
pub struct Erc8004Prover {
    config: ProverConfig,
    id: String,
}

impl Erc8004Prover {
    /// The agent's global ID it sends in `Agent-Id`.
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl Prover for Erc8004Prover {
    fn scope(&self) -> &Scope {
        &self.config.scope
    }

    fn prove<'a>(
        &'a self,
        request: &'a mut Request,
        context: &'a ProveContext,
    ) -> BoxFuture<'a, Result<(), ProverError>> {
        Box::pin(async move {
            let message = message(
                &self.id,
                request.method().as_str(),
                &target(request.url()),
                context.created,
                &context.nonce,
            );
            let signature = self
                .config
                .signer
                .sign_message(message.as_bytes())
                .await
                .map_err(|_| ProverError::new("the agent's wallet could not sign the request"))?;
            let value = format!(
                "{}.{}.0x{}",
                context.created,
                context.nonce,
                alloy::hex::encode(signature.as_bytes())
            );
            let invalid = |_| ProverError::new("the agent headers are not valid header values");
            let id = HeaderValue::from_str(&self.id).map_err(invalid)?;
            let value = HeaderValue::from_str(&value).map_err(invalid)?;
            let headers = request.headers_mut();
            headers.insert(ID_HEADER, id);
            headers.insert(SIGNATURE_HEADER, value);
            Ok(())
        })
    }
}

/// `<origin><path><query>` of a URL, as mppx reads `origin + pathname + search`.
fn target(url: &reqwest::Url) -> String {
    let origin = url.origin().ascii_serialization();
    match url.query().filter(|query| !query.is_empty()) {
        Some(query) => format!("{origin}{}?{query}", url.path()),
        None => format!("{origin}{}", url.path()),
    }
}
