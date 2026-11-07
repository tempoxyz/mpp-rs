//! Zone payments for the Tempo charge method.
//!
//! A payer whose balance is inside a Zone pays a Tempo charge by withdrawing
//! from the Zone to the recipient with a challenge-bound memo. The Zone's
//! portal on Tempo settles the withdrawal with a `processWithdrawals` call
//! that emits `WithdrawalProcessed`, and the payer sends a `zone` Credential
//! naming that settlement transaction and the withdrawal's sender tag.
//!
//! Ported from mppx's `tempo/internal/zone.ts`.

use alloy::primitives::{address, keccak256, Address, Bytes, Log, TxKind, B256};
use alloy::sol_types::{SolCall, SolEvent};
use serde::{Deserialize, Serialize};

/// Default time a payer waits for a Zone withdrawal to settle on Tempo, as mppx's
/// `defaultSettlementTimeoutMs`.
pub const DEFAULT_SETTLEMENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// The Zone outbox predeploy, which takes withdrawal requests on every Zone.
pub const ZONE_OUTBOX: Address = address!("1c00000000000000000000000000000000000002");

/// 12-byte prefix of every Zone portal address on Tempo.
const ZONE_PORTAL_PREFIX: [u8; 12] = [0x5a, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// Zone chain IDs on Tempo mainnet start after this base.
const MAINNET_ZONE_CHAIN_ID_BASE: u64 = 421_700_000;
/// Zone chain IDs on Moderato start after this base.
const TESTNET_ZONE_CHAIN_ID_BASE: u64 = 1_424_310_000;

/// Zone portal and outbox ABIs, as viem's `Abis.zonePortal` and `Abis.zoneOutbox`.
// The generated constructor of `WithdrawalRequested` takes one argument per field.
#[allow(clippy::too_many_arguments)]
mod abi {
    alloy::sol! {
        /// A withdrawal as `ZonePortal.processWithdrawals` receives it on Tempo.
        #[derive(Debug, PartialEq, Eq)]
        struct Withdrawal {
            address token;
            bytes32 senderTag;
            address to;
            uint128 amount;
            bytes32 memo;
            uint64 gasLimit;
            uint64 fallbackNonce;
            bytes callbackData;
            bytes encryptedSender;
        }

        /// The parts of the Zone portal on Tempo that settle withdrawals.
        interface IZonePortal {
            /// Emitted for each withdrawal a portal pays out.
            event WithdrawalProcessed(
                address indexed to,
                bytes32 indexed senderTag,
                address token,
                uint128 amount,
                bool callbackSuccess
            );

            /// Pays out a batch of withdrawals.
            function processWithdrawals(Withdrawal[] withdrawals, bytes32 remainingQueue);
        }

        /// The parts of the Zone outbox that request withdrawals.
        interface IZoneOutbox {
            /// Emitted for each withdrawal request.
            event WithdrawalRequested(
                uint64 indexed withdrawalIndex,
                address indexed sender,
                address token,
                address to,
                uint128 amount,
                uint128 fee,
                bytes32 memo,
                uint64 gasLimit,
                uint64 fallbackNonce,
                bytes data,
                bytes revealTo
            );

            /// Returns the fee the outbox charges on top of a withdrawal.
            function calculateWithdrawalFee(uint64 gasLimit) external view returns (uint128 fee);

            /// Requests a withdrawal from the Zone to Tempo.
            function requestWithdrawal(
                address token,
                address to,
                uint128 amount,
                bytes32 memo,
                uint64 gasLimit,
                address zoneFallbackRecipient,
                bytes data,
                bytes revealTo
            );
        }
    }
}

pub use abi::{IZoneOutbox, IZonePortal, Withdrawal};

/// Zones a Challenge accepts withdrawals from (`methodDetails.zones`): any
/// Zone on the Challenge's chain (`true`) or a non-empty list of Zone IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Zones {
    /// Any Zone on the Challenge's chain.
    Any,
    /// Only these Zone IDs.
    Ids(Vec<u32>),
}

impl Zones {
    /// A list of accepted Zone IDs, or `None` when the list is empty or holds
    /// an invalid Zone ID (see [`is_id`]).
    pub fn ids(ids: impl IntoIterator<Item = u32>) -> Option<Self> {
        let ids: Vec<u32> = ids.into_iter().collect();
        (!ids.is_empty() && ids.iter().all(|id| is_id(u64::from(*id)))).then_some(Self::Ids(ids))
    }

    /// Whether these Zones accept withdrawals from `zone_id`.
    pub fn accepts(&self, zone_id: u32) -> bool {
        is_accepted(Some(self), zone_id)
    }
}

impl Serialize for Zones {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Any => serializer.serialize_bool(true),
            Self::Ids(ids) => ids.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Zones {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Any(bool),
            Ids(Vec<u64>),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Any(true) => Ok(Self::Any),
            Raw::Any(false) => Err(serde::de::Error::custom(
                "zones must be true or a non-empty list of Zone IDs",
            )),
            Raw::Ids(ids) => {
                if ids.is_empty() {
                    return Err(serde::de::Error::custom(
                        "zones must be true or a non-empty list of Zone IDs",
                    ));
                }
                ids.into_iter()
                    .map(|id| {
                        u32::try_from(id)
                            .ok()
                            .filter(|id| is_id(u64::from(*id)))
                            .ok_or_else(|| serde::de::Error::custom("Invalid Zone ID"))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(Self::Ids)
            }
        }
    }
}

/// Whether a value is a valid Zone ID: a positive 32-bit integer.
pub fn is_id(zone_id: u64) -> bool {
    zone_id > 0 && zone_id < (1 << 32)
}

/// Whether a Challenge's `zones` accepts withdrawals from a Zone.
pub fn is_accepted(zones: Option<&Zones>, zone_id: u32) -> bool {
    if !is_id(u64::from(zone_id)) {
        return false;
    }
    match zones {
        Some(Zones::Any) => true,
        Some(Zones::Ids(ids)) => ids.contains(&zone_id),
        None => false,
    }
}

/// The Tempo portal address of a Zone, as viem's `Addresses.zonePortal`.
///
/// Like viem, an ID inside a Zone chain ID range is read as that Zone chain
/// ID, and Zones 6 and 7 keep their legacy portal addresses.
pub fn portal_address(zone_id: u32) -> Address {
    let id = u64::from(zone_id);
    let zone_id = if (4_217_000_000..4_218_000_000).contains(&id) {
        id - 4_217_000_000
    } else if (TESTNET_ZONE_CHAIN_ID_BASE..(1 << 31)).contains(&id) {
        id - TESTNET_ZONE_CHAIN_ID_BASE
    } else if (MAINNET_ZONE_CHAIN_ID_BASE..TESTNET_ZONE_CHAIN_ID_BASE).contains(&id) {
        id - MAINNET_ZONE_CHAIN_ID_BASE
    } else {
        id
    };
    match zone_id {
        6 => address!("7069DeC4E64Fd07334A0933eDe836C17259c9B23"),
        7 => address!("3F5296303400B56271b476F5A0B9cBF74350D6Ac"),
        _ => {
            let mut bytes = [0u8; 20];
            bytes[..12].copy_from_slice(&ZONE_PORTAL_PREFIX);
            bytes[12..].copy_from_slice(&zone_id.to_be_bytes());
            Address::from(bytes)
        }
    }
}

/// Derives a Zone ID from a Zone chain ID, or `None` when the chain ID doesn't
/// follow a known Zone scheme.
///
/// Zones on Tempo mainnet and Moderato use reserved bases (`421700000` and
/// `1424310000`). Zones on any other parent chain use
/// `(parentChainId << 32) | zoneId`.
pub fn id_from_chain_id(chain_id: u64) -> Option<u32> {
    if chain_id >= 1 << 32 {
        return Some(chain_id as u32);
    }
    if chain_id > TESTNET_ZONE_CHAIN_ID_BASE && chain_id < 1_424_320_000 {
        return Some((chain_id - TESTNET_ZONE_CHAIN_ID_BASE) as u32);
    }
    if chain_id > MAINNET_ZONE_CHAIN_ID_BASE && chain_id < 421_710_000 {
        return Some((chain_id - MAINNET_ZONE_CHAIN_ID_BASE) as u32);
    }
    None
}

/// Derives the parent Tempo chain ID of a Zone chain ID, or `None` when the
/// chain ID doesn't follow a known Zone scheme.
pub fn parent_chain_id_from_chain_id(chain_id: u64) -> Option<u64> {
    if chain_id >= 1 << 32 {
        return Some(chain_id >> 32);
    }
    if chain_id > TESTNET_ZONE_CHAIN_ID_BASE && chain_id < 1_424_320_000 {
        return Some(super::MODERATO_CHAIN_ID);
    }
    if chain_id > MAINNET_ZONE_CHAIN_ID_BASE && chain_id < 421_710_000 {
        return Some(super::CHAIN_ID);
    }
    None
}

/// Derives a withdrawal's sender tag, which identifies it in the
/// `WithdrawalProcessed` event on Tempo:
/// `keccak256(abi.encodePacked(sender, txHash, fallbackNonce))`.
pub fn sender_tag(sender: Address, transaction_hash: B256, fallback_nonce: u64) -> B256 {
    let mut packed = [0u8; 20 + 32 + 8];
    packed[..20].copy_from_slice(sender.as_slice());
    packed[20..52].copy_from_slice(transaction_hash.as_slice());
    packed[52..].copy_from_slice(&fallback_nonce.to_be_bytes());
    keccak256(packed)
}

/// The `WithdrawalProcessed` event `portal` emitted for `sender_tag` among
/// a settlement receipt's logs.
pub fn find_processed_event<'a>(
    logs: impl IntoIterator<Item = &'a Log>,
    portal: Address,
    sender_tag: B256,
) -> Option<IZonePortal::WithdrawalProcessed> {
    logs.into_iter()
        .filter(|log| log.address == portal)
        .filter_map(|log| IZonePortal::WithdrawalProcessed::decode_log_data(&log.data).ok())
        .find(|event| event.senderTag == sender_tag)
}

/// The withdrawal for `sender_tag` in the calldata of a settlement
/// transaction's top-level `processWithdrawals` calls to `portal`.
pub fn find_withdrawal<'a>(
    calls: impl IntoIterator<Item = (TxKind, &'a Bytes)>,
    portal: Address,
    sender_tag: B256,
) -> Option<Withdrawal> {
    calls
        .into_iter()
        .filter(|(to, _)| *to == TxKind::Call(portal))
        .filter_map(|(_, input)| IZonePortal::processWithdrawalsCall::abi_decode(input).ok())
        .find_map(|call| {
            call.withdrawals
                .into_iter()
                .find(|withdrawal| withdrawal.senderTag == sender_tag)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_from_chain_id() {
        assert_eq!(id_from_chain_id(421_700_003), Some(3));
        assert_eq!(id_from_chain_id(1_424_310_003), Some(3));
        assert_eq!(id_from_chain_id(1337 * (1 << 32) + 1), Some(1));
        assert_eq!(id_from_chain_id(42_431), None);
    }

    #[test]
    fn test_parent_chain_id_from_chain_id() {
        assert_eq!(parent_chain_id_from_chain_id(421_700_003), Some(4_217));
        assert_eq!(parent_chain_id_from_chain_id(1_424_310_003), Some(42_431));
        assert_eq!(
            parent_chain_id_from_chain_id(1337 * (1 << 32) + 1),
            Some(1337)
        );
        assert_eq!(parent_chain_id_from_chain_id(42_431), None);
    }

    #[test]
    fn test_portal_address() {
        assert_eq!(
            portal_address(3),
            address!("5ad0000000000000000000000000000000000003")
        );
        // Values from viem's `Addresses.zonePortal`.
        assert_eq!(
            portal_address(1000),
            address!("5ad00000000000000000000000000000000003e8")
        );
        assert_eq!(
            portal_address(6),
            address!("7069DeC4E64Fd07334A0933eDe836C17259c9B23")
        );
        assert_eq!(
            portal_address(1_424_310_003),
            address!("5ad0000000000000000000000000000000000003")
        );
        assert_eq!(
            portal_address(u32::MAX),
            address!("5ad00000000000000000000000000000ffffffff")
        );
    }

    #[test]
    fn test_is_accepted() {
        assert!(is_accepted(Some(&Zones::Any), 9));
        assert!(is_accepted(Some(&Zones::Ids(vec![3, 7])), 7));
        assert!(!is_accepted(Some(&Zones::Ids(vec![3, 7])), 4));
        assert!(!is_accepted(Some(&Zones::Any), 0));
        assert!(!is_accepted(None, 3));
    }

    #[test]
    fn test_zones_serde() {
        assert_eq!(
            serde_json::to_value(Zones::Any).unwrap(),
            serde_json::json!(true)
        );
        assert_eq!(
            serde_json::to_value(Zones::Ids(vec![3, 7])).unwrap(),
            serde_json::json!([3, 7])
        );
        assert_eq!(
            serde_json::from_value::<Zones>(serde_json::json!(true)).unwrap(),
            Zones::Any
        );
        assert_eq!(
            serde_json::from_value::<Zones>(serde_json::json!([3])).unwrap(),
            Zones::Ids(vec![3])
        );
        for invalid in [
            serde_json::json!(false),
            serde_json::json!([]),
            serde_json::json!([0]),
            serde_json::json!([4_294_967_296u64]),
            serde_json::json!([-1]),
            serde_json::json!([1.5]),
        ] {
            assert!(
                serde_json::from_value::<Zones>(invalid.clone()).is_err(),
                "{invalid}"
            );
        }
        assert_eq!(Zones::ids([3, 7]), Some(Zones::Ids(vec![3, 7])));
        assert_eq!(Zones::ids([]), None);
        assert_eq!(Zones::ids([0]), None);
    }

    #[test]
    fn test_sender_tag_matches_encode_packed() {
        let sender = Address::repeat_byte(0x11);
        let hash = B256::repeat_byte(0x22);
        let mut packed = Vec::new();
        packed.extend_from_slice(sender.as_slice());
        packed.extend_from_slice(hash.as_slice());
        packed.extend_from_slice(&5u64.to_be_bytes());
        assert_eq!(sender_tag(sender, hash, 5), keccak256(packed));
    }

    #[test]
    fn test_abi_selectors() {
        // Signatures of viem's `Abis.zonePortal` and `Abis.zoneOutbox`.
        assert_eq!(
            IZonePortal::processWithdrawalsCall::SIGNATURE,
            "processWithdrawals((address,bytes32,address,uint128,bytes32,uint64,uint64,bytes,bytes)[],bytes32)"
        );
        assert_eq!(
            IZonePortal::WithdrawalProcessed::SIGNATURE,
            "WithdrawalProcessed(address,bytes32,address,uint128,bool)"
        );
        assert_eq!(
            IZoneOutbox::requestWithdrawalCall::SIGNATURE,
            "requestWithdrawal(address,address,uint128,bytes32,uint64,address,bytes,bytes)"
        );
    }
}
