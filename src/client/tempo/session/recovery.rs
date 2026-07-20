//! Store-independent TIP-1034 channel recovery.

use alloy::{
    primitives::{Address, B256},
    providers::Provider,
    sol_types::SolCall,
};
use tempo_alloy::{
    contracts::precompiles::{ITIP20ChannelReserve, TIP20_CHANNEL_RESERVE_ADDRESS},
    rpc::TempoTransactionRequest,
    TempoNetwork,
};

use super::{
    channel_ops::{
        compute_precompile_channel_id_from_descriptor_with_escrow,
        encode_precompile_get_channel_state_call,
    },
    store::StoredChannelEntry,
};
use crate::{
    error::{MppError, ResultExt},
    protocol::methods::tempo::{
        precompile_voucher::verify_precompile_voucher_signature,
        session::{ChannelDescriptor, SessionSnapshot},
    },
};

/// Current mutable state read from the TIP-1034 precompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnChainChannelState {
    /// Cumulative value already settled on-chain.
    pub settled: u128,
    /// Total channel deposit.
    pub deposit: u128,
    /// Close-request timestamp, or zero while reusable.
    pub close_requested_at: u64,
}

/// Read mutable TIP-1034 channel state by channel ID.
pub async fn read_on_chain_channel_state<P: Provider<TempoNetwork>>(
    provider: &P,
    channel_id: B256,
) -> Result<OnChainChannelState, MppError> {
    let mut request = TempoTransactionRequest::default();
    request.inner = request.inner.to(TIP20_CHANNEL_RESERVE_ADDRESS).input(
        alloy::rpc::types::TransactionInput::new(encode_precompile_get_channel_state_call(
            channel_id,
        )),
    );
    let result = provider
        .call(request)
        .await
        .mpp_http("failed to read TIP-1034 channel state")?;
    let decoded = ITIP20ChannelReserve::getChannelStateCall::abi_decode_returns(&result)
        .mpp_http("failed to decode TIP-1034 channel state")?;
    Ok(OnChainChannelState {
        settled: decoded.settled.to::<u128>(),
        deposit: decoded.deposit.to::<u128>(),
        close_requested_at: u64::from(decoded.closeRequestedAt),
    })
}

/// Expected identity for a reusable payment scope.
#[derive(Debug, Clone, Copy)]
pub struct RecoveryScope {
    /// Root payer account.
    pub payer: Address,
    /// Voucher authority controlled by the client.
    pub authorized_signer: Address,
    /// Protected service payee.
    pub payee: Address,
    /// TIP-20 token.
    pub token: Address,
    /// TIP-1034 escrow/precompile.
    pub escrow: Address,
    /// EVM chain ID.
    pub chain_id: u64,
}

/// Reconcile a locally stored entry with its descriptor and on-chain state.
pub fn recover_stored_channel(
    mut entry: StoredChannelEntry,
    scope: RecoveryScope,
    state: OnChainChannelState,
) -> Result<StoredChannelEntry, MppError> {
    validate_descriptor(&entry.descriptor, entry.channel_id, scope)?;
    if entry.escrow != scope.escrow || entry.chain_id != scope.chain_id {
        return Err(invalid("stored channel scope does not match the challenge"));
    }
    if state.deposit == 0 || state.close_requested_at != 0 {
        return Err(invalid("stored channel is absent or closing on-chain"));
    }
    let cumulative = entry.cumulative_amount.max(state.settled);
    if cumulative > state.deposit {
        return Err(invalid(
            "stored cumulative amount exceeds the on-chain channel deposit",
        ));
    }
    entry.cumulative_amount = cumulative;
    entry.deposit = state.deposit;
    entry.opened = true;
    Ok(entry)
}

/// Hydrate a fresh client store from a server snapshot plus on-chain state.
pub fn hydrate_session_snapshot(
    snapshot: &SessionSnapshot,
    scope: RecoveryScope,
    state: OnChainChannelState,
) -> Result<StoredChannelEntry, MppError> {
    let channel_id = parse_b256("snapshot channelId", &snapshot.channel_id)?;
    let escrow = parse_address("snapshot escrow", &snapshot.escrow)?;
    if snapshot.chain_id != scope.chain_id || escrow != scope.escrow {
        return Err(invalid(
            "snapshot chain or escrow does not match the challenge",
        ));
    }
    validate_descriptor(&snapshot.descriptor, channel_id, scope)?;

    let signed = snapshot
        .highest_voucher
        .as_ref()
        .ok_or_else(|| invalid("session snapshot is missing its highest signed voucher"))?;
    let voucher_channel_id = parse_b256("snapshot voucher channelId", &signed.channel_id)?;
    if voucher_channel_id != channel_id {
        return Err(invalid(
            "snapshot voucher channelId does not match snapshot channelId",
        ));
    }

    let accepted = parse_amount("snapshot acceptedCumulative", &snapshot.accepted_cumulative)?;
    let voucher_cumulative = parse_amount(
        "snapshot voucher cumulativeAmount",
        &signed.cumulative_amount,
    )?;
    let required = parse_amount("snapshot requiredCumulative", &snapshot.required_cumulative)?;
    let snapshot_deposit = parse_amount("snapshot deposit", &snapshot.deposit)?;
    let snapshot_settled = parse_amount("snapshot settled", &snapshot.settled)?;
    let spent = parse_amount("snapshot spent", &snapshot.spent)?;
    if voucher_cumulative != accepted {
        return Err(invalid(
            "snapshot voucher amount does not match acceptedCumulative",
        ));
    }
    if spent > accepted || snapshot_settled > snapshot_deposit {
        return Err(invalid("snapshot amounts are inconsistent"));
    }
    if state.deposit == 0 || state.close_requested_at != 0 {
        return Err(invalid("snapshot channel is absent or closing on-chain"));
    }

    let signature = alloy::hex::decode(signed.signature.trim_start_matches("0x"))
        .map_err(|e| invalid(format!("invalid snapshot voucher signature: {e}")))?;
    let authority = descriptor_authority(&snapshot.descriptor)?;
    if !verify_precompile_voucher_signature(
        &signature,
        authority,
        channel_id,
        voucher_cumulative,
        escrow,
        snapshot.chain_id,
    )? {
        return Err(invalid("snapshot highest voucher signature is invalid"));
    }

    let cumulative_amount = accepted.max(required).max(state.settled);
    if cumulative_amount > state.deposit {
        return Err(invalid(
            "recovered cumulative amount exceeds the on-chain channel deposit",
        ));
    }
    Ok(StoredChannelEntry {
        channel_id,
        cumulative_amount,
        deposit: state.deposit,
        descriptor: snapshot.descriptor.clone(),
        escrow,
        chain_id: snapshot.chain_id,
        opened: true,
    })
}

fn validate_descriptor(
    descriptor: &ChannelDescriptor,
    channel_id: B256,
    scope: RecoveryScope,
) -> Result<(), MppError> {
    let payer = parse_address("descriptor payer", &descriptor.payer)?;
    let payee = parse_address("descriptor payee", &descriptor.payee)?;
    let token = parse_address("descriptor token", &descriptor.token)?;
    let authority = descriptor_authority(descriptor)?;
    if payer != scope.payer
        || payee != scope.payee
        || token != scope.token
        || authority != scope.authorized_signer
    {
        return Err(invalid(
            "channel descriptor identity does not match the challenge",
        ));
    }
    let expected = compute_precompile_channel_id_from_descriptor_with_escrow(
        descriptor,
        scope.escrow,
        scope.chain_id,
    )?;
    if expected != channel_id {
        return Err(invalid("channelId does not match its descriptor"));
    }
    Ok(())
}

fn descriptor_authority(descriptor: &ChannelDescriptor) -> Result<Address, MppError> {
    let authority = parse_address("descriptor authorizedSigner", &descriptor.authorized_signer)?;
    if authority == Address::ZERO {
        parse_address("descriptor payer", &descriptor.payer)
    } else {
        Ok(authority)
    }
}

fn parse_address(label: &str, value: &str) -> Result<Address, MppError> {
    value
        .parse()
        .map_err(|e| invalid(format!("invalid {label}: {e}")))
}

fn parse_b256(label: &str, value: &str) -> Result<B256, MppError> {
    value
        .parse()
        .map_err(|e| invalid(format!("invalid {label}: {e}")))
}

fn parse_amount(label: &str, value: &str) -> Result<u128, MppError> {
    value
        .parse()
        .map_err(|e| invalid(format!("invalid {label}: {e}")))
}

fn invalid(message: impl Into<String>) -> MppError {
    MppError::InvalidConfig(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        client::tempo::{
            session::channel_ops::build_channel_descriptor,
            signing::{P256Jwk, TempoP256Signer},
        },
        protocol::methods::tempo::{
            precompile_voucher::sign_precompile_voucher_primitive, session::SnapshotVoucher,
        },
    };
    use alloy::signers::Signer;
    use tempo_alloy::contracts::precompiles::TIP20_CHANNEL_RESERVE_ADDRESS;

    #[tokio::test]
    async fn reads_tip1034_channel_state_via_alloy_provider() {
        use alloy::{
            primitives::{Bytes, Uint},
            providers::{mock::Asserter, ProviderBuilder},
            sol_types::SolCall,
        };

        let state = ITIP20ChannelReserve::ChannelState {
            settled: Uint::<96, 2>::from(123u64),
            deposit: Uint::<96, 2>::from(1_000u64),
            closeRequestedAt: 0,
        };
        let response =
            Bytes::from(ITIP20ChannelReserve::getChannelStateCall::abi_encode_returns(&state));
        let asserter = Asserter::new();
        asserter.push_success(&response);
        let provider =
            ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter);

        let actual = read_on_chain_channel_state(&provider, B256::repeat_byte(0x11))
            .await
            .unwrap();
        assert_eq!(
            actual,
            OnChainChannelState {
                settled: 123,
                deposit: 1_000,
                close_requested_at: 0,
            }
        );
    }

    fn signer() -> TempoP256Signer {
        TempoP256Signer::from_webcrypto_jwk(&P256Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "OtOGGpViE5JRa7WT7wVYPtLlhm9ctiYKMBcjf9ibkK8".into(),
            y: "0JYcfjcHWmeRo5xh9WKVsCttJlZ7YV5gqkHuHI6DOI0".into(),
            d: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI".into(),
        })
        .unwrap()
    }

    fn descriptor(authority: Address) -> ChannelDescriptor {
        build_channel_descriptor(
            Address::repeat_byte(0x10),
            Address::repeat_byte(0x20),
            Address::ZERO,
            Address::repeat_byte(0x30),
            B256::repeat_byte(0x40),
            authority,
            B256::repeat_byte(0x50),
        )
    }

    fn scope(authority: Address) -> RecoveryScope {
        RecoveryScope {
            payer: Address::repeat_byte(0x10),
            authorized_signer: authority,
            payee: Address::repeat_byte(0x20),
            token: Address::repeat_byte(0x30),
            escrow: TIP20_CHANNEL_RESERVE_ADDRESS,
            chain_id: 4217,
        }
    }

    #[test]
    fn stored_recovery_uses_highest_local_or_settled_boundary() {
        let authority = signer().address();
        let descriptor = descriptor(authority);
        let channel_id = compute_precompile_channel_id_from_descriptor_with_escrow(
            &descriptor,
            TIP20_CHANNEL_RESERVE_ADDRESS,
            4217,
        )
        .unwrap();
        let recovered = recover_stored_channel(
            StoredChannelEntry {
                channel_id,
                cumulative_amount: 200,
                deposit: 900,
                descriptor,
                escrow: TIP20_CHANNEL_RESERVE_ADDRESS,
                chain_id: 4217,
                opened: true,
            },
            scope(authority),
            OnChainChannelState {
                settled: 300,
                deposit: 1_000,
                close_requested_at: 0,
            },
        )
        .unwrap();
        assert_eq!(recovered.cumulative_amount, 300);
        assert_eq!(recovered.deposit, 1_000);
    }

    #[tokio::test]
    async fn snapshot_hydration_verifies_p256_voucher() {
        let signer = signer();
        let descriptor = descriptor(signer.address());
        let channel_id = compute_precompile_channel_id_from_descriptor_with_escrow(
            &descriptor,
            TIP20_CHANNEL_RESERVE_ADDRESS,
            4217,
        )
        .unwrap();
        let signature = sign_precompile_voucher_primitive(&signer, channel_id, 200, 4217)
            .await
            .unwrap();
        let snapshot = SessionSnapshot {
            accepted_cumulative: "200".into(),
            chain_id: 4217,
            channel_id: format!("{channel_id:#x}"),
            close_requested_at: None,
            deposit: "1000".into(),
            descriptor,
            escrow: format!("{TIP20_CHANNEL_RESERVE_ADDRESS:#x}"),
            highest_voucher: Some(SnapshotVoucher {
                channel_id: format!("{channel_id:#x}"),
                cumulative_amount: "200".into(),
                signature: alloy::hex::encode_prefixed(signature),
            }),
            required_cumulative: "250".into(),
            settled: "0".into(),
            spent: "200".into(),
            units: None,
        };
        let entry = hydrate_session_snapshot(
            &snapshot,
            scope(signer.address()),
            OnChainChannelState {
                settled: 0,
                deposit: 1_000,
                close_requested_at: 0,
            },
        )
        .unwrap();
        assert_eq!(entry.cumulative_amount, 250);
    }
}
