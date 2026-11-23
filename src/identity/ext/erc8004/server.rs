//! ERC-8004 agents on the server: a verifier and a payment check, as mppx's `Erc8004.Server`.

use std::fmt;
use std::future::Future;
use std::sync::Arc;

use alloy::eips::BlockId;
use alloy::network::TransactionBuilder;
use alloy::primitives::{eip191_hash_message, Address, Bytes, Signature};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::client::RpcClient;
use alloy::rpc::json_rpc::{RequestPacket, ResponsePacket};
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;
use alloy::transports::{TransportError, TransportErrorKind, TransportFut, TransportResult};
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

    interface IERC1271 {
        function isValidSignature(bytes32 hash, bytes signature) external view returns (bytes4);
    }
}

/// The ERC-1271 magic value a contract returns for a valid signature.
const ERC1271_MAGIC: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];

/// How long a registry or ERC-1271 call may take before the chain counts as unavailable.
const RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Gas an ERC-1271 check may use: room for a passkey (P-256) verification in
/// Solidity, far below a node's default `eth_call` cap.
const ERC1271_GAS: u64 = 1_000_000;

/// Bytes of an RPC reply the default provider reads at most. The calls here
/// return one or a few 32-byte words.
const MAX_RPC_RESPONSE: usize = 64 * 1024;

/// The longest `Agent-Signature` header read. A smart-account signature is
/// a few kilobytes of hex at most.
const MAX_SIGNATURE_HEADER: usize = 16 * 1024;

/// Seconds a nonce claim outlives the signature's last accepted second, so a
/// verifier whose clock runs behind the store's still finds the claim.
const CLAIM_GRACE: u64 = 300;

/// Whether the agent's wallet signed a request.
enum Signed {
    Yes,
    No,
    /// The chain could not answer the ERC-1271 call.
    Unavailable,
}

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
    require_signature: bool,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("origin", &self.origin)
            .field("chain_id", &self.chain_id)
            .field("registry", &self.registry)
            .field("rpc_url", &self.rpc_url.as_deref().map(redacted))
            .field("require_signature", &self.require_signature)
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
            require_signature: false,
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

    /// A provider for the registry's chain. Default: an HTTP provider for
    /// [`rpc_url`](Self::rpc_url) that follows no redirects and reads replies
    /// of up to 64 KiB.
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
    ///
    /// Each claim is kept up to twelve minutes. A store that cannot expire
    /// keys, such as [`FileStore`](crate::store::FileStore), keeps every
    /// claim for good, one entry per signed request: use one that expires
    /// them, such as [`MemoryStore`](crate::store::MemoryStore) or a SQL or
    /// Redis store.
    pub fn store(mut self, store: Arc<dyn Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Requires the agent's request signature on the paid retry too, rather
    /// than accepting a `tempo` charge from the agent's wallet as proof of the
    /// agent. Use it when the tempo method settles through a relay
    /// (`tempo::RelayConfig`), which matches the Credential's source to its
    /// signer away from this server.
    pub fn require_signature(mut self) -> Self {
        self.require_signature = true;
        self
    }

    /// Decides whether a verified agent may call the API, such as by its ID
    /// or reputation. It runs only on an agent whose wallet signed the request.
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
/// Calls reach the chain before any Credential is checked, so each is bounded:
/// five seconds, 1,000,000 gas for ERC-1271, at the latest block. Alloy's RPC
/// client logs each request at TRACE, including the ERC-1271 call's signature:
/// keep `alloy_rpc_client` below TRACE where logs are kept, or use a store so
/// a logged signature is already spent.
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
                Url::parse(url).map_err(|_| ConfigError("The RPC URL is not a URL.".to_owned()))?;
            let local = alloy::transports::utils::guess_local_url(url.as_str());
            let client = RpcClient::new(RpcTransport::new(url)?, local);
            ProviderBuilder::new().connect_client(client).erased()
        }
    };
    let core = Arc::new(Core {
        origin,
        provider,
        requires: vec![Requirement::new(TYPE)],
        lookup: MemoKey::new(),
        signed: MemoKey::new(),
        admitted: MemoKey::new(),
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
    /// One signature check per request.
    signed: MemoKey,
    /// One `allow` decision and nonce claim per request, so a nonce is spent once.
    admitted: MemoKey,
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
        Box::pin(async move { self.core.admitted(request).await })
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
                !core.config.require_signature
                    && input.challenge.method.as_str() == "tempo"
                    && input.challenge.intent.as_str() == "charge"
                    && matches!(
                        credential.payload.get("type").and_then(Value::as_str),
                        Some("transaction" | "proof")
                    )
            });
            let Some(credential) = binds_source else {
                return core.admitted(input.request).await;
            };
            // The tempo method matches the source to the payment's signer only
            // when it settles, after this check. So `allow` runs only on an
            // agent whose wallet also signed the request; without `allow`, the
            // payment alone proves the agent, as in mppx.
            let signs =
                core.config.allow.is_some() || input.request.header(SIGNATURE_HEADER).is_some();
            let agent = if signs {
                core.authenticated(input.request)
                    .await
                    .map(|(agent, _)| agent)
            } else {
                core.lookup(input.request).await
            };
            let agent = match agent {
                Verification::Valid(agent) => agent,
                rejected => return rejected,
            };
            // The source is a did:pkh:eip155:<chainId>:<address>.
            let chain_id = core.config.chain_id;
            let parts: Vec<&str> = credential
                .source
                .as_deref()
                .unwrap_or_default()
                .splitn(6, ':')
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
            if signs {
                return core.admitted(input.request).await;
            }
            Verification::Valid(agent)
        })
    }
}

/// A verified signature's nonce, still to be claimed.
#[derive(Clone)]
struct Claim {
    nonce: String,
    /// The last second the signature is accepted.
    expires: u64,
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
            .memoize(&self.lookup, Box::pin(self.read_agent(request)))
            .await
    }

    // Each memoized step is boxed: nested inline, the futures outgrow a test thread's stack.
    async fn authenticated(&self, request: &IdentityRequest) -> Verification<(Agent, Claim)> {
        request
            .memoize(&self.signed, Box::pin(self.verify_signature(request)))
            .await
    }

    async fn admitted(&self, request: &IdentityRequest) -> Verification<Agent> {
        request
            .memoize(&self.admitted, Box::pin(self.admit(request)))
            .await
    }

    /// The agent that signed the request, if `allow` lets it in: then its
    /// nonce is claimed, so a denied agent holds no claim. A spent signature
    /// is rejected before `allow` runs.
    async fn admit(&self, request: &IdentityRequest) -> Verification<Agent> {
        let (agent, claim) = match self.authenticated(request).await {
            Verification::Valid(signed) => signed,
            Verification::Rejected(rejection) => return rejection.into(),
        };
        let key = format!(
            "mppx:erc8004:nonce:{}",
            eip191_hash_message(format!("{}:{}", agent.id, claim.nonce))
        );
        // Read-only, so a denied agent still holds no claim; the claim below
        // stays atomic for concurrent requests.
        if let (Some(store), Some(_)) = (&self.config.store, &self.config.allow) {
            match store.get(&key).await {
                Ok(None) => {}
                Ok(Some(_)) => {
                    return Rejection::invalid("The agent signature was already used.").into()
                }
                Err(_) => return Rejection::unavailable("The replay store is unavailable.").into(),
            }
        }
        let agent = match self.allowed(Verification::Valid(agent)).await {
            Verification::Valid(agent) => agent,
            rejected => return rejected,
        };
        if let Some(store) = &self.config.store {
            // Held past expiry: the signature still verifies through the whole
            // second `now == expires`, and on verifiers whose clocks run behind
            // the store's.
            let ttl = claim.expires.saturating_sub(now()) + 1 + CLAIM_GRACE;
            match store
                .put_if_absent_with_ttl(
                    &key,
                    Value::Bool(true),
                    std::time::Duration::from_secs(ttl),
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return Rejection::invalid("The agent signature was already used.").into()
                }
                Err(_) => return Rejection::unavailable("The replay store is unavailable.").into(),
            }
        }
        // The wallet, `allow` and the store may have taken a while.
        if now() > claim.expires {
            return Rejection::invalid("The agent signature has expired.").into();
        }
        Verification::Valid(agent)
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
        let contract = IIdentityRegistry::new(registry, &self.provider);
        let call = contract.getAgentWallet(agent.agent_id);
        let wallet = match tokio::time::timeout(RPC_TIMEOUT, call.call()).await {
            Ok(Ok(wallet)) => wallet,
            Ok(Err(_)) | Err(_) => {
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
    async fn verify_signature(&self, request: &IdentityRequest) -> Verification<(Agent, Claim)> {
        let agent = match self.lookup(request).await {
            Verification::Valid(agent) => agent,
            Verification::Rejected(rejection) => return rejection.into(),
        };
        let malformed =
            || Rejection::invalid("The agent signature is missing or malformed.").into();
        let header = request.header(SIGNATURE_HEADER).unwrap_or_default();
        if header.len() > MAX_SIGNATURE_HEADER {
            return malformed();
        }
        let mut parts = header.splitn(4, '.');
        let (Some(created), Some(nonce), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return malformed();
        };
        let signature = signature
            .strip_prefix("0x")
            .filter(|hex| !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()));
        let created = Some(created)
            .filter(|created| {
                !created.is_empty()
                    && created.len() <= 12
                    && created.bytes().all(|b| b.is_ascii_digit())
            })
            .and_then(|created| created.parse::<u64>().ok());
        let (Some(created), Some(signature)) = (created, signature) else {
            return malformed();
        };
        if nonce.is_empty() {
            return malformed();
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
        match self.signed_by(agent.wallet, &message, signature).await {
            Signed::Yes => {}
            Signed::No => {
                return Rejection::invalid("The agent's wallet did not sign the request.").into()
            }
            Signed::Unavailable => {
                return Rejection::unavailable("The agent's wallet could not be checked.").into()
            }
        }
        let claim = Claim {
            nonce: nonce.to_owned(),
            expires,
        };
        Verification::Valid((agent, claim))
    }

    /// Returns whether `wallet` signed `message`: by EOA recovery, else by ERC-1271.
    ///
    /// A revert, an error response or any return other than the ABI-encoded
    /// magic value (empty for a plain EOA) is [`Signed::No`]; a transport
    /// failure or timeout is [`Signed::Unavailable`], so a contract wallet is
    /// told to retry rather than that it didn't sign.
    async fn signed_by(&self, wallet: Address, message: &str, signature: &str) -> Signed {
        let Ok(bytes) = alloy::hex::decode(signature) else {
            return Signed::No;
        };
        let recovered = Signature::try_from(bytes.as_slice())
            .ok()
            .and_then(|signature| signature.recover_address_from_msg(message).ok());
        if recovered == Some(wallet) {
            return Signed::Yes;
        }
        let data = IERC1271::isValidSignatureCall {
            hash: eip191_hash_message(message),
            signature: Bytes::from(bytes),
        }
        .abi_encode();
        let call = TransactionRequest::default()
            .with_to(wallet)
            .with_input(data)
            .with_gas_limit(ERC1271_GAS);
        // The latest block, as the registry read: never pending state.
        let call = self.provider.call(call).block(BlockId::latest());
        match tokio::time::timeout(RPC_TIMEOUT, call).await {
            Ok(Ok(output)) if is_magic(&output) => Signed::Yes,
            Ok(Err(error)) if error.as_error_resp().is_none() => Signed::Unavailable,
            Ok(_) => Signed::No,
            Err(_) => Signed::Unavailable,
        }
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

/// The default provider's HTTP transport: it follows no redirects, so only the
/// configured endpoint answers, and reads at most [`MAX_RPC_RESPONSE`] bytes of
/// a reply.
#[derive(Clone)]
struct RpcTransport {
    client: reqwest::Client,
    url: Url,
}

impl RpcTransport {
    fn new(url: Url) -> Result<Self, ConfigError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(RPC_TIMEOUT)
            .build()
            .map_err(|_| ConfigError("The RPC client could not be built.".to_owned()))?;
        Ok(Self { client, url })
    }

    async fn send(self, request: RequestPacket) -> TransportResult<ResponsePacket> {
        let mut response = self
            .client
            .post(self.url)
            .json(&request)
            .send()
            .await
            .map_err(TransportErrorKind::custom)?;
        let too_large = || TransportErrorKind::custom_str("The RPC reply is too large.");
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RPC_RESPONSE as u64)
        {
            return Err(too_large());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(TransportErrorKind::custom)? {
            if body.len() + chunk.len() > MAX_RPC_RESPONSE {
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        let status = response.status();
        if !status.is_success() {
            // A redirect lands here too: it is never followed.
            return Err(TransportErrorKind::http_error(
                status.as_u16(),
                String::from_utf8_lossy(&body).into_owned(),
            ));
        }
        serde_json::from_slice(&body)
            .map_err(|error| TransportError::deser_err(error, String::from_utf8_lossy(&body)))
    }
}

impl tower_service::Service<RequestPacket> for RpcTransport {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        Box::pin(self.clone().send(request))
    }
}

/// Whether an `isValidSignature` return is exactly the ABI-encoded magic
/// value: one 32-byte word, the magic left-aligned and the rest zero.
fn is_magic(output: &[u8]) -> bool {
    output.len() == 32 && output[..4] == ERC1271_MAGIC && output[4..].iter().all(|&byte| byte == 0)
}

/// `scheme://host[:port]` of a URL, without its userinfo, path or query, which
/// can carry a provider key.
fn redacted(url: &str) -> String {
    match Url::parse(url) {
        Ok(url) => match (url.host_str(), url.port()) {
            (Some(host), Some(port)) => format!("{}://{host}:{port}", url.scheme()),
            (Some(host), None) => format!("{}://{host}", url.scheme()),
            (None, _) => format!("{}:", url.scheme()),
        },
        Err(_) => "<not a URL>".to_owned(),
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
