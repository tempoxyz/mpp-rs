//! Fee payer envelope (magic byte 0x78).
//!
//! This is a helper encoding used for fee-sponsored transactions.
//!
//! It is **not** a broadcastable Tempo transaction type. Instead, clients send a
//! `0x78 || rlp([...])` envelope to a sponsoring server, which validates the
//! envelope, reconstitutes a normal 0x76 Tempo transaction, attaches a
//! `fee_payer_signature`, and then broadcasts.
//!
//! Note: this envelope format is specific to mpp-rs. The TypeScript/Viem SDK
//! (mppx) achieves fee sponsorship differently — the client sends a standard
//! `0x76` transaction to a JSON-RPC sidecar (`Handler.feePayer()` in tempo-ts)
//! via viem's `withFeePayer` transport, which cosigns using
//! `signTransaction({ feePayer: account })` and returns a complete `0x76`.
//! The `0x78` envelope exists in mpp-rs because it embeds the fee-payer flow
//! inline in the MPP credential exchange rather than using a separate RPC hop.

use std::num::NonZeroU64;

use alloy::eips::eip2930::AccessList;
use alloy::primitives::{Address, Bytes, U256};
use alloy::rlp::{Buf, BufMut, Decodable, Encodable, Error as RlpError, Header, EMPTY_STRING_CODE};

use tempo_primitives::transaction::{
    Call, SignedKeyAuthorization, TempoSignature, TempoSignedAuthorization,
};

/// Fee payer envelope magic byte.
///
/// Tempo primitives defines this as the fee payer signature domain-separation
/// magic byte.
pub const TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID: u8 =
    tempo_primitives::transaction::tempo_transaction::FEE_PAYER_SIGNATURE_MAGIC_BYTE;

/// RLP payload sent by a client when requesting fee sponsorship.
///
/// Wire format: `0x78 || rlp([ chainId, maxPriorityFeePerGas, maxFeePerGas, gasLimit, calls,
/// accessList, nonceKey, nonce, validBefore?, validAfter?, feeToken?, senderAddress,
/// authorizationList, keyAuthorization?, signatureEnvelope ])`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeePayerEnvelope78 {
    pub chain_id: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub calls: Vec<Call>,
    pub access_list: AccessList,
    pub nonce_key: U256,
    pub nonce: u64,
    pub valid_before: Option<u64>,
    pub valid_after: Option<u64>,
    pub fee_token: Option<Address>,
    pub sender: Address,
    pub tempo_authorization_list: Vec<TempoSignedAuthorization>,
    pub key_authorization: Option<SignedKeyAuthorization>,
    pub signature: TempoSignature,
}

impl FeePayerEnvelope78 {
    /// Build an envelope from a transaction the client is signing.
    ///
    /// The provided `tx` is expected to be in the “fee payer signing shape”:
    /// - `fee_token == None` (server chooses fee token)
    /// - `fee_payer_signature.is_some()` placeholder (so `signature_hash()` skips fee_token)
    pub fn from_signing_tx(
        tx: tempo_primitives::transaction::TempoTransaction,
        sender: Address,
        signature: TempoSignature,
    ) -> Self {
        Self {
            chain_id: tx.chain_id,
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
            max_fee_per_gas: tx.max_fee_per_gas,
            gas_limit: tx.gas_limit,
            calls: tx.calls,
            access_list: tx.access_list,
            nonce_key: tx.nonce_key,
            nonce: tx.nonce,
            valid_before: tx.valid_before.map(|v| v.get()),
            valid_after: tx.valid_after.map(|v| v.get()),
            fee_token: tx.fee_token,
            sender,
            tempo_authorization_list: tx.tempo_authorization_list,
            key_authorization: tx.key_authorization,
            signature,
        }
    }

    /// Encode full envelope bytes, including the leading magic byte `0x78`.
    #[must_use]
    pub fn encoded_envelope(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.length());
        out.put_u8(TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID);
        self.encode(&mut out);
        out
    }

    /// Decode full envelope bytes, including the leading magic byte `0x78`.
    pub fn decode_envelope(mut bytes: &[u8]) -> alloy::rlp::Result<Self> {
        if bytes.is_empty() {
            return Err(RlpError::InputTooShort);
        }

        let magic = bytes[0];
        bytes.advance(1);
        if magic != TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID {
            return Err(RlpError::Custom("invalid fee payer envelope magic byte"));
        }

        let env = Self::decode(&mut bytes)?;
        if !bytes.is_empty() {
            return Err(RlpError::UnexpectedLength);
        }
        Ok(env)
    }

    /// Reconstitute a normal Tempo 0x76 transaction for signature recovery.
    ///
    /// This sets the `fee_payer_signature` placeholder so Tempo's signing hash
    /// skips `fee_token` (the user did not commit to a particular fee token).
    #[must_use]
    pub fn to_recoverable_signed(&self) -> tempo_primitives::AASigned {
        let tx = tempo_primitives::TempoTransaction {
            chain_id: self.chain_id,
            nonce: self.nonce,
            nonce_key: self.nonce_key,
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            fee_token: self.fee_token,
            calls: self.calls.clone(),
            access_list: self.access_list.clone(),
            fee_payer_signature: Some(alloy::primitives::Signature::new(
                U256::ZERO,
                U256::ZERO,
                false,
            )),
            valid_before: self.valid_before.and_then(NonZeroU64::new),
            valid_after: self.valid_after.and_then(NonZeroU64::new),
            key_authorization: self.key_authorization.clone(),
            tempo_authorization_list: self.tempo_authorization_list.clone(),
        };

        tempo_primitives::AASigned::new_unhashed(tx, self.signature.clone())
    }
}

impl Encodable for FeePayerEnvelope78 {
    fn encode(&self, out: &mut dyn BufMut) {
        Header {
            list: true,
            payload_length: self.payload_length(),
        }
        .encode(out);

        self.chain_id.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.calls.encode(out);
        self.access_list.encode(out);
        self.nonce_key.encode(out);
        self.nonce.encode(out);

        match self.valid_before {
            Some(v) => v.encode(out),
            None => out.put_u8(EMPTY_STRING_CODE),
        }
        match self.valid_after {
            Some(v) => v.encode(out),
            None => out.put_u8(EMPTY_STRING_CODE),
        }
        match self.fee_token {
            Some(a) => a.encode(out),
            None => out.put_u8(EMPTY_STRING_CODE),
        }

        self.sender.encode(out);
        self.tempo_authorization_list.encode(out);

        if let Some(key_authorization) = &self.key_authorization {
            key_authorization.encode(out);
        }

        self.signature.encode(out);
    }

    fn length(&self) -> usize {
        Header {
            list: true,
            payload_length: self.payload_length(),
        }
        .length_with_payload()
    }
}

impl FeePayerEnvelope78 {
    fn payload_length(&self) -> usize {
        let mut payload_length = 0usize;
        payload_length += self.chain_id.length();
        payload_length += self.max_priority_fee_per_gas.length();
        payload_length += self.max_fee_per_gas.length();
        payload_length += self.gas_limit.length();
        payload_length += self.calls.length();
        payload_length += self.access_list.length();
        payload_length += self.nonce_key.length();
        payload_length += self.nonce.length();

        payload_length += self.valid_before.map_or(1, |v| v.length());
        payload_length += self.valid_after.map_or(1, |v| v.length());
        payload_length += self.fee_token.map_or(1, |v| v.length());

        payload_length += self.sender.length();
        payload_length += self.tempo_authorization_list.length();
        if let Some(key_authorization) = &self.key_authorization {
            payload_length += key_authorization.length();
        }
        payload_length += self.signature.length();
        payload_length
    }

    fn decode_optional<T: Decodable>(buf: &mut &[u8]) -> alloy::rlp::Result<Option<T>> {
        match buf.first() {
            Some(b) if *b == EMPTY_STRING_CODE => {
                buf.advance(1);
                Ok(None)
            }
            Some(_) => Ok(Some(T::decode(buf)?)),
            None => Err(RlpError::InputTooShort),
        }
    }
}

impl Decodable for FeePayerEnvelope78 {
    fn decode(buf: &mut &[u8]) -> alloy::rlp::Result<Self> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(RlpError::UnexpectedString);
        }

        if header.payload_length > buf.len() {
            return Err(RlpError::InputTooShort);
        }

        let mut fields_buf = &buf[..header.payload_length];

        let chain_id: u64 = Decodable::decode(&mut fields_buf)?;
        let max_priority_fee_per_gas: u128 = Decodable::decode(&mut fields_buf)?;
        let max_fee_per_gas: u128 = Decodable::decode(&mut fields_buf)?;
        let gas_limit: u64 = Decodable::decode(&mut fields_buf)?;
        let calls: Vec<Call> = Decodable::decode(&mut fields_buf)?;
        let access_list: AccessList = Decodable::decode(&mut fields_buf)?;
        let nonce_key: U256 = Decodable::decode(&mut fields_buf)?;
        let nonce: u64 = Decodable::decode(&mut fields_buf)?;

        let valid_before: Option<u64> = Self::decode_optional(&mut fields_buf)?;
        let valid_after: Option<u64> = Self::decode_optional(&mut fields_buf)?;
        let fee_token: Option<Address> = Self::decode_optional(&mut fields_buf)?;

        let sender: Address = Decodable::decode(&mut fields_buf)?;
        let tempo_authorization_list: Vec<TempoSignedAuthorization> =
            Decodable::decode(&mut fields_buf)?;

        // key_authorization is truly optional; if present it's an RLP list. If absent, the next
        // element is the signature envelope bytes.
        let key_authorization: Option<SignedKeyAuthorization> = match fields_buf.first() {
            Some(b) if *b >= 0xc0 => Some(Decodable::decode(&mut fields_buf)?),
            Some(_) => None,
            None => return Err(RlpError::InputTooShort),
        };

        // Signature envelope is RLP bytes.
        let sig_bytes: Bytes = Decodable::decode(&mut fields_buf)?;
        let signature = TempoSignature::from_bytes(&sig_bytes)
            .map_err(|_| RlpError::Custom("invalid signature envelope"))?;

        if !fields_buf.is_empty() {
            return Err(RlpError::UnexpectedLength);
        }
        buf.advance(header.payload_length);

        Ok(Self {
            chain_id,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            calls,
            access_list,
            nonce_key,
            nonce,
            valid_before,
            valid_after,
            fee_token,
            sender,
            tempo_authorization_list,
            key_authorization,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Bytes, TxKind};
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use tempo_primitives::transaction::{
        Call, KeyAuthorization, PrimitiveSignature, SignatureType, TempoTransaction, TokenLimit,
    };

    fn test_signer() -> PrivateKeySigner {
        "0x1234567890123456789012345678901234567890123456789012345678901234"
            .parse()
            .unwrap()
    }

    /// Build a minimal fee-payer-shaped tx (fee_token=None, placeholder fp sig,
    /// expiring nonce key, valid_before set).
    fn base_fee_payer_tx() -> TempoTransaction {
        TempoTransaction {
            chain_id: 42431,
            nonce: 1,
            gas_limit: 500_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            fee_token: None,
            calls: vec![Call {
                to: TxKind::Call(Address::repeat_byte(0x22)),
                value: U256::ZERO,
                input: Bytes::from_static(&[0xaa, 0xbb]),
            }],
            nonce_key: U256::MAX,
            key_authorization: None,
            access_list: Default::default(),
            fee_payer_signature: Some(alloy::primitives::Signature::new(
                U256::ZERO,
                U256::ZERO,
                false,
            )),
            valid_before: NonZeroU64::new(9999999999),
            valid_after: None,
            tempo_authorization_list: vec![],
        }
    }

    /// Sign a tx and produce a `FeePayerEnvelope78`.
    fn sign_envelope(tx: TempoTransaction, signer: &PrivateKeySigner) -> FeePayerEnvelope78 {
        let sig_hash = tx.signature_hash();
        let inner_sig = signer.sign_hash_sync(&sig_hash).unwrap();
        let signature = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(inner_sig));
        FeePayerEnvelope78::from_signing_tx(tx, signer.address(), signature)
    }

    fn make_signed_key_auth(signer: &PrivateKeySigner) -> SignedKeyAuthorization {
        let auth = KeyAuthorization {
            chain_id: 42431,
            key_type: SignatureType::Secp256k1,
            key_id: signer.address(),
            expiry: NonZeroU64::new(9999999999),
            limits: Some(vec![TokenLimit {
                token: Address::repeat_byte(0x33),
                limit: U256::from(1_000_000u64),
                period: 0,
            }]),
            allowed_calls: None,
        };
        let inner_sig = signer.sign_hash_sync(&auth.signature_hash()).unwrap();
        auth.into_signed(PrimitiveSignature::Secp256k1(inner_sig))
    }

    /// Assert encode→decode roundtrip preserves all fields.
    fn assert_roundtrip(original: &FeePayerEnvelope78) {
        let bytes = original.encoded_envelope();
        assert_eq!(
            bytes[0], TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID,
            "envelope must start with 0x78"
        );
        let decoded =
            FeePayerEnvelope78::decode_envelope(&bytes).expect("decode_envelope should succeed");
        assert_eq!(&decoded, original);
    }

    // ---- roundtrip tests ----

    #[test]
    fn roundtrip_minimal_no_optionals() {
        let signer = test_signer();
        let mut tx = base_fee_payer_tx();
        tx.valid_before = None;
        tx.valid_after = None;

        let env = sign_envelope(tx, &signer);
        assert!(env.valid_before.is_none());
        assert!(env.valid_after.is_none());
        assert!(env.fee_token.is_none());
        assert!(env.key_authorization.is_none());
        assert_roundtrip(&env);
    }

    #[test]
    fn roundtrip_with_valid_before() {
        let signer = test_signer();
        let tx = base_fee_payer_tx(); // valid_before = Some(9999999999)

        let env = sign_envelope(tx, &signer);
        assert!(env.valid_before.is_some());
        assert!(env.valid_after.is_none());
        assert_roundtrip(&env);
    }

    #[test]
    fn roundtrip_with_valid_before_and_after() {
        let signer = test_signer();
        let mut tx = base_fee_payer_tx();
        tx.valid_after = NonZeroU64::new(1000);

        let env = sign_envelope(tx, &signer);
        assert!(env.valid_before.is_some());
        assert!(env.valid_after.is_some());
        assert_roundtrip(&env);
    }

    #[test]
    fn roundtrip_with_fee_token() {
        let signer = test_signer();
        let mut tx = base_fee_payer_tx();
        tx.fee_token = Some(Address::repeat_byte(0x44));

        let env = sign_envelope(tx, &signer);
        assert_eq!(env.fee_token, Some(Address::repeat_byte(0x44)));
        assert_roundtrip(&env);
    }

    #[test]
    fn roundtrip_all_optionals_set() {
        let signer = test_signer();
        let mut tx = base_fee_payer_tx();
        tx.valid_after = NonZeroU64::new(500);
        tx.fee_token = Some(Address::repeat_byte(0x55));

        let env = sign_envelope(tx, &signer);
        assert!(env.valid_before.is_some());
        assert!(env.valid_after.is_some());
        assert!(env.fee_token.is_some());
        assert_roundtrip(&env);
    }

    #[test]
    fn roundtrip_with_key_authorization() {
        let signer = test_signer();
        let mut tx = base_fee_payer_tx();
        tx.key_authorization = Some(make_signed_key_auth(&signer));

        let env = sign_envelope(tx, &signer);
        assert!(env.key_authorization.is_some());
        assert_roundtrip(&env);
    }

    #[test]
    fn roundtrip_with_key_authorization_and_all_optionals() {
        let signer = test_signer();
        let mut tx = base_fee_payer_tx();
        tx.valid_after = NonZeroU64::new(42);
        tx.fee_token = Some(Address::repeat_byte(0x66));
        tx.key_authorization = Some(make_signed_key_auth(&signer));

        let env = sign_envelope(tx, &signer);
        assert!(env.key_authorization.is_some());
        assert!(env.valid_before.is_some());
        assert!(env.valid_after.is_some());
        assert!(env.fee_token.is_some());
        assert_roundtrip(&env);
    }

    #[test]
    fn roundtrip_multiple_calls() {
        let signer = test_signer();
        let mut tx = base_fee_payer_tx();
        tx.calls = vec![
            Call {
                to: TxKind::Call(Address::repeat_byte(0x11)),
                value: U256::from(100u64),
                input: Bytes::from_static(&[0x01]),
            },
            Call {
                to: TxKind::Call(Address::repeat_byte(0x22)),
                value: U256::ZERO,
                input: Bytes::from_static(&[0x02, 0x03, 0x04]),
            },
            Call {
                to: TxKind::Call(Address::repeat_byte(0x33)),
                value: U256::from(999u64),
                input: Bytes::new(),
            },
        ];

        let env = sign_envelope(tx, &signer);
        assert_eq!(env.calls.len(), 3);
        assert_roundtrip(&env);
    }

    #[test]
    fn roundtrip_empty_calls() {
        let signer = test_signer();
        let mut tx = base_fee_payer_tx();
        tx.calls = vec![];

        let env = sign_envelope(tx, &signer);
        assert!(env.calls.is_empty());
        assert_roundtrip(&env);
    }

    #[test]
    fn roundtrip_with_keychain_signature() {
        use tempo_primitives::transaction::KeychainSignature;

        let signer = test_signer();
        let tx = base_fee_payer_tx();
        let sig_hash = tx.signature_hash();
        let inner_sig = signer.sign_hash_sync(&sig_hash).unwrap();

        let wallet = Address::repeat_byte(0xAB);
        let keychain_sig = KeychainSignature::new(wallet, PrimitiveSignature::Secp256k1(inner_sig));
        let signature = TempoSignature::Keychain(keychain_sig);

        let env = FeePayerEnvelope78::from_signing_tx(tx, wallet, signature);
        assert_roundtrip(&env);
    }
}
