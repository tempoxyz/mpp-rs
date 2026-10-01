//! Voucher signature canonicalization.
//!
//! A voucher is signed once; the fuzzer then supplies the signature bytes and
//! the voucher fields to verify. `verify_voucher` never panics and accepts
//! exactly one signature per encoding for the signed voucher: the 65-byte
//! form with `v` of 27/28 and the 64-byte ERC-2098 form. High-s twins,
//! `v` of 0/1, padded or truncated signatures, and any other amount, channel,
//! chain, contract or signer are rejected.

#![no_main]

use std::future::Future;
use std::pin::pin;
use std::sync::LazyLock;
use std::task::{Context, Poll, Waker};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mpp::protocol::methods::tempo::{sign_voucher, voucher::verify_voucher};
use mpp::{Address, PrivateKeySigner};

const CHAIN_ID: u64 = 42431;
const CHANNEL_ID: [u8; 32] = [0x11; 32];
const AMOUNT: u128 = 1_000_000;
const ESCROW: Address = Address::repeat_byte(0x22);
/// secp256k1 group order.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

struct Signed {
    signer: Address,
    /// `r || s || v` with `v` of 27/28.
    signature: [u8; 65],
}

static SIGNED: LazyLock<Signed> = LazyLock::new(|| {
    let signer: PrivateKeySigner =
        "0x1234567890123456789012345678901234567890123456789012345678901234"
            .parse()
            .expect("valid key");
    let signing = sign_voucher(&signer, CHANNEL_ID.into(), AMOUNT, ESCROW, CHAIN_ID);
    // Local signers resolve on the first poll.
    let Poll::Ready(signature) = pin!(signing).poll(&mut Context::from_waker(Waker::noop())) else {
        unreachable!("local signing does not suspend");
    };
    let signature = signature.expect("signing succeeds");
    Signed {
        signer: signer.address(),
        signature: <[u8; 65]>::try_from(&signature[..]).expect("65 bytes"),
    }
});

#[derive(Debug, Arbitrary)]
struct Input {
    signature: SignatureInput,
    fields: Option<Fields>,
}

#[derive(Debug, Arbitrary)]
enum SignatureInput {
    /// The signature as signed, XORed with a mask.
    Masked(Vec<u8>),
    /// `(r, n - s)` with the recovery id flipped: valid ECDSA, not canonical.
    HighS,
    /// The signature with `v` rewritten.
    Parity(u8),
    /// `r || yParityAndS`.
    Erc2098,
    Resized(u8),
    Raw(Vec<u8>),
}

#[derive(Debug, Arbitrary)]
struct Fields {
    channel_id: [u8; 32],
    amount: u128,
    chain_id: u64,
    escrow: [u8; 20],
    signer: [u8; 20],
}

impl SignatureInput {
    fn build(&self, signed: &[u8; 65]) -> Vec<u8> {
        let mut bytes = signed.to_vec();
        match self {
            Self::Masked(mask) => {
                for (byte, mask) in bytes.iter_mut().zip(mask) {
                    *byte ^= mask;
                }
            }
            Self::HighS => {
                let mut borrow = 0;
                for i in (0..32).rev() {
                    let (diff, b1) = N[i].overflowing_sub(bytes[32 + i]);
                    let (diff, b2) = diff.overflowing_sub(borrow);
                    bytes[32 + i] = diff;
                    borrow = u8::from(b1 || b2);
                }
                bytes[64] ^= 27 ^ 28;
            }
            Self::Parity(v) => bytes[64] = *v,
            Self::Erc2098 => {
                bytes[32] |= (bytes[64] - 27) << 7;
                bytes.truncate(64);
            }
            Self::Resized(len) => bytes.resize(*len as usize, 0),
            Self::Raw(raw) => bytes = raw.clone(),
        }
        bytes
    }
}

fuzz_target!(|input: Input| {
    let signed = &*SIGNED;
    let signature = input.signature.build(&signed.signature);

    let mut erc2098 = signed.signature[..64].to_vec();
    erc2098[32] |= (signed.signature[64] - 27) << 7;
    let canonical = signature == signed.signature || signature == erc2098;

    let accepted = match &input.fields {
        None => verify_voucher(
            ESCROW,
            CHAIN_ID,
            CHANNEL_ID.into(),
            AMOUNT,
            &signature,
            signed.signer,
        ),
        Some(fields) => {
            let same = fields.channel_id == CHANNEL_ID
                && fields.amount == AMOUNT
                && fields.chain_id == CHAIN_ID
                && Address::from(fields.escrow) == ESCROW
                && Address::from(fields.signer) == signed.signer;
            let accepted = verify_voucher(
                fields.escrow.into(),
                fields.chain_id,
                fields.channel_id.into(),
                fields.amount,
                &signature,
                fields.signer.into(),
            );
            assert!(!accepted || same, "accepted for other fields: {fields:?}");
            accepted
        }
    };
    if input.fields.is_none() {
        assert_eq!(accepted, canonical, "{:?}", input.signature);
    }
});
