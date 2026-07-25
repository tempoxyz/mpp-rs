//! Tempo transaction signing through `tempo-alloy` wallets and fillers.

pub mod keychain;

use alloy::{
    eips::{eip2930::AccessList, Encodable2718},
    network::NetworkWallet,
    providers::{Provider, SendableTx},
};
use tempo_alloy::{
    accounts::{TempoWallet, TempoWalletFillable},
    rpc::TempoTransactionRequest,
    TempoNetwork,
};
use tempo_primitives::{
    transaction::{AASigned, TempoTransaction},
    TempoTxEnvelope,
};

pub use tempo_alloy::accounts::{P256Jwk, P256SignerError, TempoP256Signer, TempoPrimitiveSigner};

use crate::{
    error::{MppError, ResultExt},
    protocol::methods::tempo::FeePayerEnvelope78,
};

/// Wallet type used by the native Tempo client.
pub type NativeTempoWallet = TempoWallet<TempoPrimitiveSigner>;

/// Fill account metadata and resolve a pending one-time authorization without
/// signing the request.
///
/// MPP uses this before its capped gas-estimation call. Final signing still
/// runs the wallet filler again, so a key publication racing the estimate
/// cannot cause a stale authorization to be replayed.
pub(crate) async fn prepare_wallet_request<P>(
    provider: &P,
    wallet: &NativeTempoWallet,
    request: TempoTransactionRequest,
) -> Result<TempoTransactionRequest, MppError>
where
    P: Provider<TempoNetwork>,
{
    use alloy::providers::fillers::TxFiller;

    let mut sendable = SendableTx::Builder(request);
    wallet.fill_sync(&mut sendable);
    let fillable = wallet
        .prepare(
            provider,
            sendable
                .as_builder()
                .ok_or_else(|| MppError::InvalidConfig("expected Tempo request".into()))?,
        )
        .await
        .mpp_http("failed to prepare Tempo wallet")?;
    let request = sendable
        .try_into_request()
        .map_err(|_| MppError::InvalidConfig("expected unsigned Tempo request".into()))?;
    Ok(match fillable {
        TempoWalletFillable::Direct => request,
        TempoWalletFillable::Keychain(key_authorization) => TempoTransactionRequest {
            key_authorization: key_authorization.map(|authorization| *authorization),
            ..request
        },
    })
}

async fn fill_and_sign<P>(
    provider: &P,
    wallet: &NativeTempoWallet,
    transaction: TempoTransaction,
) -> Result<AASigned, MppError>
where
    P: Provider<TempoNetwork>,
{
    use alloy::providers::fillers::TxFiller;

    let mut sendable = SendableTx::Builder(transaction.into());
    wallet.fill_sync(&mut sendable);
    let fillable = wallet
        .prepare(
            provider,
            sendable
                .as_builder()
                .ok_or_else(|| MppError::InvalidConfig("expected Tempo request".into()))?,
        )
        .await
        .mpp_http("failed to prepare Tempo wallet")?;
    let envelope = wallet
        .fill(fillable, sendable)
        .await
        .mpp_http("failed to sign Tempo transaction")?
        .try_into_envelope()
        .map_err(|_| MppError::InvalidConfig("Tempo wallet did not sign transaction".into()))?;
    match envelope {
        TempoTxEnvelope::AA(signed) => Ok(signed),
        _ => Err(MppError::InvalidConfig(
            "MPP requires a Tempo AA transaction".into(),
        )),
    }
}

/// Resolve the wallet's access-key state, sign, and EIP-2718 encode a Tempo
/// transaction.
pub async fn sign_and_encode_wallet<P>(
    provider: &P,
    wallet: &NativeTempoWallet,
    transaction: TempoTransaction,
) -> Result<Vec<u8>, MppError>
where
    P: Provider<TempoNetwork>,
{
    Ok(fill_and_sign(provider, wallet, transaction)
        .await?
        .encoded_2718())
}

async fn sign_prepared(
    wallet: &NativeTempoWallet,
    transaction: TempoTransaction,
) -> Result<AASigned, MppError> {
    match wallet
        .sign_request(transaction.into())
        .await
        .map_err(|error| {
            MppError::InvalidConfig(format!("failed to sign Tempo transaction: {error}"))
        })? {
        TempoTxEnvelope::AA(signed) => Ok(signed),
        _ => Err(MppError::InvalidConfig(
            "MPP requires a Tempo AA transaction".into(),
        )),
    }
}

/// Sign and encode a transaction whose access-key authorization was already
/// resolved by the caller.
///
/// Prefer [`sign_and_encode_wallet`] when an RPC provider is available.
pub async fn sign_and_encode_prepared_wallet(
    wallet: &NativeTempoWallet,
    transaction: TempoTransaction,
) -> Result<Vec<u8>, MppError> {
    Ok(sign_prepared(wallet, transaction).await?.encoded_2718())
}

/// Resolve the wallet's access-key state and sign an MPP fee-payer envelope.
pub async fn sign_and_encode_fee_payer_envelope_wallet<P>(
    provider: &P,
    wallet: &NativeTempoWallet,
    mut transaction: TempoTransaction,
) -> Result<Vec<u8>, MppError>
where
    P: Provider<TempoNetwork>,
{
    validate_fee_payer_transaction(&transaction)?;
    transaction.access_list = AccessList::default();

    let (transaction, signature, _) = fill_and_sign(provider, wallet, transaction)
        .await?
        .into_parts();
    Ok(
        FeePayerEnvelope78::from_signing_tx(transaction, wallet.account(), signature)
            .encoded_envelope(),
    )
}

/// Sign an MPP fee-payer envelope whose access-key authorization was already
/// resolved by the caller.
///
/// Prefer [`sign_and_encode_fee_payer_envelope_wallet`] when an RPC provider
/// is available.
pub async fn sign_and_encode_prepared_fee_payer_envelope_wallet(
    wallet: &NativeTempoWallet,
    mut transaction: TempoTransaction,
) -> Result<Vec<u8>, MppError> {
    validate_fee_payer_transaction(&transaction)?;
    transaction.access_list = AccessList::default();

    let (transaction, signature, _) = sign_prepared(wallet, transaction).await?.into_parts();
    Ok(
        FeePayerEnvelope78::from_signing_tx(transaction, wallet.account(), signature)
            .encoded_envelope(),
    )
}

fn validate_fee_payer_transaction(transaction: &TempoTransaction) -> Result<(), MppError> {
    if transaction.fee_payer_signature.is_none() {
        return Err(MppError::InvalidConfig(
            "fee payer envelope requires a fee_payer_signature placeholder".into(),
        ));
    }
    if transaction.fee_token.is_some() {
        return Err(MppError::InvalidConfig(
            "fee payer envelope must not include fee_token".into(),
        ));
    }
    if transaction.nonce_key != alloy::primitives::U256::MAX {
        return Err(MppError::InvalidConfig(
            "fee payer envelope must use the expiring nonce key".into(),
        ));
    }
    if transaction.valid_before.is_none() {
        return Err(MppError::InvalidConfig(
            "fee payer envelope must include valid_before".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy::{
        primitives::{Address, Bytes, TxKind, U256},
        providers::ProviderBuilder,
        signers::local::PrivateKeySigner,
    };
    use tempo_primitives::transaction::{Call, TempoSignature};

    use super::*;

    fn transaction() -> TempoTransaction {
        TempoTransaction {
            chain_id: 42431,
            nonce: 1,
            gas_limit: 500_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            fee_token: Some(Address::repeat_byte(0x33)),
            calls: vec![Call {
                to: TxKind::Call(Address::repeat_byte(0x22)),
                value: U256::ZERO,
                input: Bytes::from_static(&[0xaa, 0xbb]),
            }],
            nonce_key: U256::ZERO,
            key_authorization: None,
            access_list: Default::default(),
            fee_payer_signature: None,
            valid_before: None,
            valid_after: None,
            tempo_authorization_list: vec![],
        }
    }

    fn signer() -> TempoPrimitiveSigner {
        "0x1234567890123456789012345678901234567890123456789012345678901234"
            .parse::<PrivateKeySigner>()
            .unwrap()
            .into()
    }

    #[tokio::test]
    async fn wallet_owns_direct_and_keychain_signature_shape() {
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(Default::default());

        let direct = fill_and_sign(&provider, &TempoWallet::new(signer()), transaction())
            .await
            .unwrap();
        assert!(matches!(direct.signature(), TempoSignature::Primitive(_)));

        let account = Address::repeat_byte(0x44);
        let keychain = fill_and_sign(
            &provider,
            &TempoWallet::for_account(account, signer()),
            transaction(),
        )
        .await
        .unwrap();
        let TempoSignature::Keychain(signature) = keychain.signature() else {
            panic!("expected keychain signature");
        };
        assert_eq!(signature.user_address, account);
        assert!(!signature.is_legacy());
    }
}
