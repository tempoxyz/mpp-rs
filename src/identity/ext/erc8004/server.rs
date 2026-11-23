//! ERC-8004 agents on the server: a verifier and a payment check, as mppx's `Erc8004.Server`.

use std::fmt;
use std::future::Future;
use std::sync::Arc;

use alloy::primitives::{eip191_hash_message, Address, Bytes, FixedBytes, Signature};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use reqwest::Url;
use serde_json::Value;

use super::constants::{
    CHAIN_ID, CLOCK_TOLERANCE, IDENTITY_REGISTRY, ID_HEADER, MAX_AGE, RPC_URL, SIGNATURE_HEADER,
    TYPE,
};
use super::{message, Agent, AgentRef};
use crate::identity::{
    BoxFuture, Handle, IdentityRequest, MemoKey, PaymentCheck, PaymentCheckInput, Rejection,
    RejectionStatus, Requirement, Verification, Verifier,
};
use crate::store::Store;

alloy::sol! {
    #[sol(rpc)]
    interface IIdentityRegistry {
        function getAgentWallet(uint256 agentId) external view returns (address);
    }

    #[sol(rpc)]
    interface IERC1271 {
        function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4);
    }
}

/// The ERC-1271 magic value a contract returns for a valid signature.
const ERC1271_MAGIC: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];

/// Decides whether a verified agent may call the API.
pub type AllowFn = Arc<dyn Fn(&Agent) -> BoxFuture<'static, bool> + Send + Sync>;

/// ERC-8004 server options, as mppx's `Erc8004.Server.create` config.
#[derive(Clone)]
pub struct Config {
    origin: String,
    allow: Option<AllowFn>,
    chain_id: u64,
    registry: Address,
    provider: Option<DynProvider>,
    rpc_url: Option<String>,
    store: Option<Arc<dyn Store>>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("origin", &self.origin)
            .field("chain_id", &self.chain_id)
            .field("registry", &self.registry)
            .field("rpc_url", &self.rpc_url)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// Accepts agents of the Identity Registry on Tempo mainnet, for the API
    /// at `origin`, such as `https://api.example`.
    ///
    /// The agent signs the request's full URL. mppx reads it from the
    /// request; a Rust server often sees only the path, and the `Host` header
    /// and an absolute-form request target are the client's to choose, so the
    /// origin is configured instead.
    pub fn new(origin: impl Into<String>) -> Self {
        Self {
            origin: origin.into(),
            allow: None,
            chain_id: CHAIN_ID,
            registry: IDENTITY_REGISTRY,
            provider: None,
            rpc_url: None,
            store: None,
        }
    }

    /// The registry's chain. Payments must settle on it too. Default: 4217
    /// (Tempo mainnet). Another chain needs a [`provider`](Self::provider)
    /// or an [`rpc_url`](Self::rpc_url).
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// The Identity Registry. Default: `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`.
    pub fn registry(mut self, registry: Address) -> Self {
        self.registry = registry;
        self
    }

    /// A provider for the registry's chain. Default: an HTTP provider for [`rpc_url`](Self::rpc_url).
    pub fn provider(mut self, provider: DynProvider) -> Self {
        self.provider = Some(provider);
        self
    }

    /// RPC URL of the registry's chain. Default: `https://rpc.tempo.xyz`.
    pub fn rpc_url(mut self, rpc_url: impl Into<String>) -> Self {
        self.rpc_url = Some(rpc_url.into());
        self
    }

    /// Accepts each request signature once. Without it, a signature can be
    /// replayed for six minutes. The store must implement
    /// `put_if_absent_with_ttl` atomically.
    pub fn store(mut self, store: Arc<dyn Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Decides whether a verified agent may call the API, such as by its ID
    /// or reputation.
    pub fn allow<F>(self, allow: F) -> Self
    where
        F: Fn(&Agent) -> bool + Send + Sync + 'static,
    {
        self.allow_async(move |agent| std::future::ready(allow(agent)))
    }

    /// Like [`allow`](Self::allow), deciding asynchronously.
    pub fn allow_async<F, Fut>(mut self, allow: F) -> Self
    where
        F: Fn(&Agent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send + 'static,
    {
        self.allow = Some(Arc::new(move |agent| Box::pin(allow(agent))));
        self
    }
}

/// Why [`create`] refused a [`Config`].
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(String);

/// An ERC-8004 agent verifier from [`create`].
#[derive(Clone, Debug)]
pub struct Erc8004 {
    /// A request-stage verifier: requires a request signed by the agent's wallet, before any 402.
    pub verifier: Handle<Erc8004Verifier>,
    /// A payment check: requires that the agent's wallet paid.
    pub payment_check: Handle<Erc8004PaymentCheck>,
}

/// Creates an ERC-8004 agent verifier for one API, as mppx's `Erc8004.Server.create`.
///
/// - [`verifier`](Erc8004::verifier) requires a request signed by the
///   agent's wallet, as the Identity Registry's `getAgentWallet` names it:
///   an EOA signature, or ERC-1271 for a contract or configurable account.
/// - [`payment_check`](Erc8004::payment_check) accepts a `tempo` charge the
///   agent's wallet signed (a transaction or proof), so the payment itself
///   proves the agent. For anything else (no Credential, transaction hashes,
///   sessions, Zones, other methods) it requires the signature.
///
/// Fails when the origin is not a URL, or when a chain other than Tempo
/// mainnet has no provider or RPC URL.
pub fn create(config: Config) -> Result<Erc8004, ConfigError> {
    let origin = Url::parse(&config.origin)
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .filter(|origin| origin != "null")
        .ok_or_else(|| ConfigError(format!("`{}` is not an origin.", config.origin)))?;
    if config.provider.is_none() && config.rpc_url.is_none() && config.chain_id != CHAIN_ID {
        return Err(ConfigError(
            "Pass a provider or an RPC URL for a chain other than Tempo mainnet.".to_owned(),
        ));
    }
    let provider = match &config.provider {
        Some(provider) => provider.clone(),
        None => {
            let url = config.rpc_url.as_deref().unwrap_or(RPC_URL);
            let url =
                Url::parse(url).map_err(|_| ConfigError(format!("`{url}` is not an RPC URL.")))?;
            ProviderBuilder::new().connect_http(url).erased()
        }
    };
    let core = Arc::new(Core {
        origin,
        provider,
        requires: vec![Requirement::new(TYPE)],
        lookup: MemoKey::new(),
        signed: MemoKey::new(),
        config,
    });
    Ok(Erc8004 {
        verifier: Handle::new(Erc8004Verifier { core: core.clone() }),
        payment_check: Handle::new(Erc8004PaymentCheck { core }),
    })
}

struct Core {
    config: Config,
    origin: String,
    provider: DynProvider,
    requires: Vec<Requirement>,
    /// One registry lookup per request, shared by the verifier and payment check.
    lookup: MemoKey,
    /// One signature check per request, so a nonce is spent once.
    signed: MemoKey,
}

/// The request-stage verifier of [`Erc8004`].
pub struct Erc8004Verifier {
    core: Arc<Core>,
}

/// The payment check of [`Erc8004`].
pub struct Erc8004PaymentCheck {
    core: Arc<Core>,
}

impl Verifier for Erc8004Verifier {
    type Value = Agent;

    fn verify<'a>(&'a self, request: &'a IdentityRequest) -> BoxFuture<'a, Verification<Agent>> {
        Box::pin(async move {
            let signed = self.core.signed(request).await;
            self.core.allowed(signed).await
        })
    }
}

impl PaymentCheck for Erc8004PaymentCheck {
    type Value = Agent;

    fn requires(&self) -> &[Requirement] {
        &self.core.requires
    }

    fn verify<'a>(&'a self, input: PaymentCheckInput<'a>) -> BoxFuture<'a, Verification<Agent>> {
        Box::pin(async move {
            let core = &self.core;
            // Only a tempo charge the source signed binds it to the payer: a
            // transaction or a proof. A hash credential doesn't (the charge can
            // accept another sender), and neither do sessions, Zones or other
            // methods, so they need the agent's signature instead.
            let binds_source = input.credential.filter(|credential| {
                input.challenge.method.as_str() == "tempo"
                    && input.challenge.intent.as_str() == "charge"
                    && matches!(
                        credential.payload.get("type").and_then(Value::as_str),
                        Some("transaction" | "proof")
                    )
            });
            let Some(credential) = binds_source else {
                let signed = core.signed(input.request).await;
                return core.allowed(signed).await;
            };
            let agent = match core.lookup(input.request).await {
                Verification::Valid(agent) => agent,
                rejected => return rejected,
            };
            // The source is a did:pkh:eip155:<chainId>:<address>.
            let chain_id = core.config.chain_id;
            let parts: Vec<&str> = credential
                .source
                .as_deref()
                .unwrap_or_default()
                .split(':')
                .collect();
            let account = match parts.as_slice() {
                ["did", "pkh", "eip155", chain, address] if *chain == chain_id.to_string() => {
                    parse_address(address)
                }
                _ => None,
            };
            let Some(account) = account else {
                return Rejection::invalid(format!(
                    "The payment must name its source account on chain {chain_id}."
                ))
                .into();
            };
            if account != agent.wallet {
                return Rejection::forbidden("The payment is not from the agent's wallet.").into();
            }
            core.allowed(Verification::Valid(agent)).await
        })
    }
}

impl Core {
    /// Runs `allow` on a verified agent.
    async fn allowed(&self, result: Verification<Agent>) -> Verification<Agent> {
        let (Verification::Valid(agent), Some(allow)) = (&result, &self.config.allow) else {
            return result;
        };
        if allow(agent).await {
            return result;
        }
        Rejection::forbidden("This agent may not call this API.").into()
    }

    async fn lookup(&self, request: &IdentityRequest) -> Verification<Agent> {
        request
            .memoize(&self.lookup, self.read_agent(request))
            .await
    }

    async fn signed(&self, request: &IdentityRequest) -> Verification<Agent> {
        request
            .memoize(&self.signed, self.verify_signature(request))
            .await
    }

    /// Reads the request's agent and its wallet from the registry.
    async fn read_agent(&self, request: &IdentityRequest) -> Verification<Agent> {
        let Some(id) = request.header(ID_HEADER).filter(|id| !id.is_empty()) else {
            return Rejection::new(RejectionStatus::Missing)
                .with_reason("Sign the request as an ERC-8004 agent.")
                .into();
        };
        let chain_id = self.config.chain_id;
        let registry = self.config.registry;
        let Some(agent) = AgentRef::parse(id)
            .filter(|agent| agent.chain_id == chain_id && agent.registry == registry)
        else {
            return Rejection::invalid(format!(
                "The agent must be in the Identity Registry {} on chain {chain_id}.",
                registry.to_checksum(None)
            ))
            .into();
        };
        let wallet = match IIdentityRegistry::new(registry, &self.provider)
            .getAgentWallet(agent.agent_id)
            .call()
            .await
        {
            Ok(wallet) => wallet,
            Err(_) => {
                return Rejection::unavailable("The Identity Registry is unavailable.").into()
            }
        };
        if wallet == Address::ZERO {
            return Rejection::forbidden("The agent has no wallet.").into();
        }
        Verification::Valid(Agent {
            id: agent.format(),
            agent_id: agent.agent_id,
            wallet,
        })
    }

    /// Checks that the agent's wallet signed this request.
    async fn verify_signature(&self, request: &IdentityRequest) -> Verification<Agent> {
        let agent = match self.lookup(request).await {
            Verification::Valid(agent) => agent,
            rejected => return rejected,
        };
        let header = request.header(SIGNATURE_HEADER).unwrap_or_default();
        let parts: Vec<&str> = header.split('.').collect();
        let [created, nonce, signature] = parts.as_slice() else {
            return Rejection::invalid("The agent signature is missing or malformed.").into();
        };
        let signature = signature
            .strip_prefix("0x")
            .filter(|hex| !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()));
        let created = Some(*created)
            .filter(|created| {
                !created.is_empty()
                    && created.len() <= 12
                    && created.bytes().all(|b| b.is_ascii_digit())
            })
            .and_then(|created| created.parse::<u64>().ok());
        let (Some(created), Some(signature)) = (created, signature) else {
            return Rejection::invalid("The agent signature is missing or malformed.").into();
        };
        if nonce.is_empty() {
            return Rejection::invalid("The agent signature is missing or malformed.").into();
        }
        let now = now();
        let expires = created + MAX_AGE + CLOCK_TOLERANCE;
        if created > now + CLOCK_TOLERANCE || expires < now {
            return Rejection::invalid("The agent signature has expired.").into();
        }

        let id = request.header(ID_HEADER).unwrap_or_default();
        let message = message(
            id,
            request.method().as_str(),
            &self.target(request),
            created,
            nonce,
        );
        if !self.signed_by(agent.wallet, &message, signature).await {
            return Rejection::invalid("The agent's wallet did not sign the request.").into();
        }
        if let Some(store) = &self.config.store {
            let key = format!(
                "mppx:erc8004:nonce:{}",
                eip191_hash_message(format!("{}:{nonce}", agent.id))
            );
            // Held one second past expiry: the signature still verifies
            // through the whole second `now == expires`.
            let ttl = std::time::Duration::from_secs(expires - now + 1);
            match store
                .put_if_absent_with_ttl(&key, Value::Bool(true), ttl)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Rejection::invalid("The agent signature was already used.").into()
                }
                Err(_) => return Rejection::unavailable("The replay store is unavailable.").into(),
            }
        }
        Verification::Valid(agent)
    }

    /// Returns whether `wallet` signed `message`: by EOA recovery, else by ERC-1271.
    async fn signed_by(&self, wallet: Address, message: &str, signature: &str) -> bool {
        let Ok(bytes) = alloy::hex::decode(signature) else {
            return false;
        };
        let recovered = Signature::try_from(bytes.as_slice())
            .ok()
            .and_then(|signature| signature.recover_address_from_msg(message).ok());
        if recovered == Some(wallet) {
            return true;
        }
        IERC1271::new(wallet, &self.provider)
            .isValidSignature(eip191_hash_message(message), Bytes::from(bytes))
            .call()
            .await
            .is_ok_and(|magic| magic == FixedBytes(ERC1271_MAGIC))
    }

    /// The origin, path and query the agent signed, on the configured origin.
    fn target(&self, request: &IdentityRequest) -> String {
        target(&self.origin, request)
    }
}

/// `<origin><path><query>` of `request` on `origin`, as mppx reads
/// `origin + pathname + search` from the request URL.
pub(super) fn target(origin: &str, request: &IdentityRequest) -> String {
    let uri = request.uri();
    let path = match uri.path() {
        "" => "/",
        path => path,
    };
    match uri.query().filter(|query| !query.is_empty()) {
        Some(query) => format!("{origin}{path}?{query}"),
        None => format!("{origin}{path}"),
    }
}

fn parse_address(value: &str) -> Option<Address> {
    let hex = value.strip_prefix("0x")?;
    if hex.len() != 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    value.parse().ok()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}
