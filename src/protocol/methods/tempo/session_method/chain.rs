//! Reading channel state from the escrow contract.

use alloy::primitives::{Address, B256};
use alloy::providers::Provider;
use tempo_alloy::TempoNetwork;

use crate::protocol::traits::VerificationError;

/// On-chain channel state from the escrow contract.
#[derive(Debug, Clone)]
pub struct OnChainChannel {
    pub payer: Address,
    pub payee: Address,
    pub token: Address,
    pub authorized_signer: Address,
    pub deposit: u128,
    pub settled: u128,
    pub close_requested_at: u64,
    pub finalized: bool,
}

/// Read channel state from the escrow contract.
///
/// Uses the `getChannel` view function on the escrow contract.
pub(super) async fn get_on_chain_channel<P: Provider<TempoNetwork>>(
    provider: &P,
    escrow_contract: Address,
    channel_id: B256,
) -> Result<OnChainChannel, VerificationError> {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface IEscrow {
            function getChannel(bytes32 channelId) external view returns (
                bool finalized,
                uint64 closeRequestedAt,
                address payer,
                address payee,
                address token,
                address authorizedSigner,
                uint128 deposit,
                uint128 settled
            );
        }
    }

    let escrow = IEscrow::new(escrow_contract, provider);
    let result = escrow.getChannel(channel_id).call().await.map_err(|e| {
        VerificationError::network_error(format!("Failed to read on-chain channel: {}", e))
    })?;

    Ok(OnChainChannel {
        payer: result.payer,
        payee: result.payee,
        token: result.token,
        deposit: result.deposit,
        settled: result.settled,
        finalized: result.finalized,
        authorized_signer: result.authorizedSigner,
        close_requested_at: result.closeRequestedAt,
    })
}
