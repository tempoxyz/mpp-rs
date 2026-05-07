#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[macro_use]
extern crate tracing;

#[cfg(not(target_family = "wasm"))]
mod ws;
#[cfg(not(target_family = "wasm"))]
pub use ws::{MppEvent, MppHandle, MppWsConnect, NoVoucher, VoucherProvider, VoucherRequest};

// Re-exports for ergonomics.
#[cfg(not(target_family = "wasm"))]
pub use mpp::{
    client::{
        ws::{WsClientMessage, WsServerMessage},
        PaymentProvider,
    },
    PaymentChallenge, PaymentCredential, Receipt,
};
