//! On-chain escrow contract ABI for stream payment channels.
//!
//! Defines the [`ITempoStreamChannel`] interface for interacting with the
//! on-chain escrow contract using alloy's `sol!` macro.
//!
//! # Contract Functions
//!
//! - `getChannel`: Read channel state
//! - `computeChannelId`: Deterministic channel ID computation
//! - `open`: Open a new channel with initial deposit
//! - `topUp`: Add funds to an existing channel
//! - `settle`: Settle a partial amount using a voucher signature
//! - `close`: Close the channel with final settlement

alloy::sol! {
    /// TempoStreamChannel escrow contract interface.
    ///
    /// This contract manages unidirectional payment channels for streaming payments.
    /// Channels are identified by a deterministic bytes32 ID computed from
    /// (payer, payee, token, authorizedSigner).
    #[sol(rpc)]
    interface ITempoStreamChannel {
        /// Get channel state from the contract.
        ///
        /// Returns the on-chain state of a payment channel.
        function getChannel(bytes32 channelId) external view returns (
            address payer,
            address payee,
            address token,
            address authorizedSigner,
            uint128 deposit,
            uint128 settledAmount,
            uint256 closeRequestedAt,
            bool finalized
        );

        /// Compute channel ID deterministically from the channel parameters.
        ///
        /// The channel ID is keccak256(abi.encode(payer, payee, token, deposit, salt, authorizedSigner)).
        function computeChannelId(
            address payer,
            address payee,
            address token,
            uint128 deposit,
            bytes32 salt,
            address authorizedSigner
        ) external pure returns (bytes32);

        /// Open a new payment channel with an initial deposit.
        ///
        /// The caller must have approved the escrow contract for the token amount.
        function open(
            address payee,
            address token,
            uint128 deposit,
            bytes32 salt,
            address authorizedSigner
        ) external returns (bytes32);

        /// Add funds to an existing channel.
        ///
        /// The caller must have approved the escrow contract for the additional amount.
        function topUp(bytes32 channelId, uint128 additionalDeposit) external;

        /// Settle a partial amount using a signed voucher.
        ///
        /// Transfers the delta (cumulativeAmount - settledAmount) to the payee.
        function settle(
            bytes32 channelId,
            uint128 cumulativeAmount,
            bytes signature
        ) external;

        /// Close the channel with final settlement.
        ///
        /// Settles any remaining amount and returns unused deposit to the payer.
        function close(
            bytes32 channelId,
            uint128 cumulativeAmount,
            bytes signature
        ) external;

        /// Request channel closure (payer-initiated).
        ///
        /// Starts a grace period after which the payer can withdraw remaining funds.
        function requestClose(bytes32 channelId) external;

        /// Withdraw remaining funds after grace period expires (payer-initiated).
        ///
        /// Can only be called after requestClose and the grace period has elapsed.
        function withdraw(bytes32 channelId) external;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_abi_compiles() {
        // The sol! macro validates the ABI at compile time.
        // This test ensures the generated types are usable.
        use super::ITempoStreamChannel;

        let _ = std::mem::size_of::<ITempoStreamChannel::getChannelCall>();
        let _ = std::mem::size_of::<ITempoStreamChannel::computeChannelIdCall>();
        let _ = std::mem::size_of::<ITempoStreamChannel::openCall>();
        let _ = std::mem::size_of::<ITempoStreamChannel::topUpCall>();
        let _ = std::mem::size_of::<ITempoStreamChannel::settleCall>();
        let _ = std::mem::size_of::<ITempoStreamChannel::closeCall>();
        let _ = std::mem::size_of::<ITempoStreamChannel::requestCloseCall>();
        let _ = std::mem::size_of::<ITempoStreamChannel::withdrawCall>();
    }
}
