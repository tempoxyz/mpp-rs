//! Native `evm/charge` payment method.
//!
//! The generic EVM charge method settles an ERC-20 transfer via an EIP-3009
//! `TransferWithAuthorization` signature, independent of any specific chain. It
//! differs from the Tempo method, which verifies on-chain TIP-20 transfers /
//! Tempo transactions rather than ERC-20 authorizations.
//!
//! This module provides the protocol layer: wire types ([`types`]) and the
//! EIP-712 signing/verification primitives ([`authorization`]).

pub mod authorization;
pub mod types;

pub use authorization::{
    challenge_nonce, evm_source, recover_authorization_signer, sign_authorization, signing_hash,
};
pub use types::{
    AuthorizationPayload, AuthorizationPayloadType, EvmMethodDetails, Split,
    CREDENTIAL_TYPE_AUTHORIZATION, METHOD,
};
