//! TIP-1107 configurable account signatures (type `0x05`), which TIP-1166 lets
//! sign TIP-1034 channel vouchers from T15.
//!
//! A configurable account is a threshold set of weighted owners. A `0x05`
//! signature carries the account, its full configuration and the owners'
//! primitive approvals of [`configurable_account_digest`]. This module ports
//! the encoding, commitment, address derivation and quorum rules of
//! `tempo-primitives`' `configurable_account` module (tempoxyz/tempo#9293),
//! which the published `tempo-primitives` does not ship yet.

use alloy::primitives::{keccak256, Address, Bytes, B256};
use alloy::rlp::{Decodable, Encodable, Header};
use tempo_alloy::primitives::transaction::{PrimitiveSignature, TempoSignature};
use tempo_alloy::primitives::MAX_WEBAUTHN_SIGNATURE_LENGTH;

/// The TIP-1107 configurable account precompile.
pub const CONFIGURABLE_ACCOUNT_ADDRESS: Address =
    alloy::primitives::address!("0xAACC000000000000000000000000000000000000");

/// Signature type byte of a configurable account signature.
pub const SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT: u8 = 0x05;

/// Domain of the digest owners sign: [`configurable_account_digest`].
pub const CONFIGURABLE_ACCOUNT_SIGNATURE_DOMAIN: &[u8] = b"tempo:configurable-account:signature";

/// Domain of a version-0 account's address derivation.
pub const CONFIGURABLE_ACCOUNT_DOMAIN: &[u8] = b"tempo:configurable-account:account";

/// Domain of a configuration commitment.
pub const CONFIGURABLE_ACCOUNT_CONFIG_DOMAIN: &[u8] = b"tempo:configurable-account:config";

/// Most owners a configuration may list.
pub const MAX_CONFIGURABLE_ACCOUNT_OWNERS: usize = 48;

/// Most owner approvals a signature may carry.
pub const MAX_CONFIGURABLE_ACCOUNT_SIGNATURES: usize = 8;

/// Largest encoded owner approval: a type byte and a WebAuthn signature.
pub const MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES: usize = 1 + MAX_WEBAUTHN_SIGNATURE_LENGTH;

/// One weighted owner of a configurable account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConfigurableAccountOwner {
    /// Owner address, recovered from its primitive approval.
    pub owner: Address,
    /// Weight the owner's approval adds toward the threshold.
    pub weight: u8,
}

/// A configurable account's configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConfigurableAccountConfig {
    /// Derivation salt of the account.
    pub salt: B256,
    /// Configuration version; `0` is the configuration the address derives from.
    pub version: u64,
    /// Approval weight a signature needs.
    pub threshold: u8,
    /// Owners in strictly ascending address order.
    pub owners: Vec<ConfigurableAccountOwner>,
}

/// Why a configuration or `0x05` signature is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigurableAccountError {
    /// The configuration lists no owners.
    EmptyOwners,
    /// The configuration lists more than [`MAX_CONFIGURABLE_ACCOUNT_OWNERS`].
    TooManyOwners,
    /// The threshold is zero.
    ZeroThreshold,
    /// An owner is the zero address.
    ZeroOwner,
    /// An owner has zero weight.
    ZeroWeight,
    /// An owner is listed twice.
    DuplicateOwner,
    /// Owners are not in ascending address order.
    OwnersNotAscending,
    /// The owners' weights add up past 255.
    TotalWeightExceedsMax,
    /// No [`MAX_CONFIGURABLE_ACCOUNT_SIGNATURES`] owners reach the threshold.
    ThresholdExceedsWeight,
    /// A version-0 configuration lists its own account as an owner.
    AccountIsOwner,
    /// The signature's account is the zero address.
    ZeroAccount,
    /// The signature carries no approvals.
    EmptySignatures,
    /// The signature carries more than [`MAX_CONFIGURABLE_ACCOUNT_SIGNATURES`] approvals.
    TooManySignatures,
    /// An approval is larger than [`MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES`].
    OwnerSignatureTooLarge,
    /// The bytes are not a canonical `0x05` signature.
    InvalidEncoding,
}

impl core::fmt::Display for ConfigurableAccountError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::EmptyOwners => "configurable account has no owners",
            Self::TooManyOwners => "configurable account has too many owners",
            Self::ZeroThreshold => "configurable account threshold is zero",
            Self::ZeroOwner => "configurable account owner is the zero address",
            Self::ZeroWeight => "configurable account owner has zero weight",
            Self::DuplicateOwner => "configurable account owner is listed twice",
            Self::OwnersNotAscending => "configurable account owners are not ascending",
            Self::TotalWeightExceedsMax => "configurable account owner weights exceed 255",
            Self::ThresholdExceedsWeight => "configurable account threshold is unreachable",
            Self::AccountIsOwner => "configurable account lists itself as an owner",
            Self::ZeroAccount => "configurable account signature names the zero address",
            Self::EmptySignatures => "configurable account signature has no approvals",
            Self::TooManySignatures => "configurable account signature has too many approvals",
            Self::OwnerSignatureTooLarge => "configurable account approval is too large",
            Self::InvalidEncoding => "invalid configurable account signature encoding",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ConfigurableAccountError {}

impl ConfigurableAccountConfig {
    /// Check the configuration's shape.
    pub fn validate(&self) -> Result<(), ConfigurableAccountError> {
        self.validate_inner(None)
    }

    /// Commitment the configurable account precompile stores for this
    /// configuration: `keccak256(domain || salt || version || threshold ||
    /// owner count || (owner || weight)...)`.
    pub fn commitment(&self) -> Result<B256, ConfigurableAccountError> {
        self.validate()?;
        Ok(self.commitment_unchecked())
    }

    /// Address a version-0 configuration derives: `keccak256(domain || salt ||
    /// threshold || owner count || (owner || weight)...)`.
    pub fn account_address(&self) -> Result<Address, ConfigurableAccountError> {
        self.validate()?;
        Ok(self.account_address_unchecked())
    }

    /// Weight of `owner`, if the configuration lists it.
    pub fn owner_weight(&self, owner: Address) -> Option<u8> {
        self.owners
            .binary_search_by_key(&owner, |entry| entry.owner)
            .ok()
            .map(|index| self.owners[index].weight)
    }

    fn commitment_unchecked(&self) -> B256 {
        let mut input = Vec::with_capacity(
            CONFIGURABLE_ACCOUNT_CONFIG_DOMAIN.len() + 32 + 8 + 2 + self.owners.len() * 21,
        );
        input.extend_from_slice(CONFIGURABLE_ACCOUNT_CONFIG_DOMAIN);
        input.extend_from_slice(self.salt.as_slice());
        input.extend_from_slice(&self.version.to_be_bytes());
        self.append_owner_set(&mut input);
        keccak256(input)
    }

    fn account_address_unchecked(&self) -> Address {
        let mut input =
            Vec::with_capacity(CONFIGURABLE_ACCOUNT_DOMAIN.len() + 32 + 2 + self.owners.len() * 21);
        input.extend_from_slice(CONFIGURABLE_ACCOUNT_DOMAIN);
        input.extend_from_slice(self.salt.as_slice());
        self.append_owner_set(&mut input);
        Address::from_word(keccak256(input))
    }

    fn append_owner_set(&self, input: &mut Vec<u8>) {
        input.push(self.threshold);
        // `validate` caps owners at 48, so the count fits a byte.
        input.push(self.owners.len() as u8);
        for owner in &self.owners {
            input.extend_from_slice(owner.owner.as_slice());
            input.push(owner.weight);
        }
    }

    fn validate_inner(&self, account: Option<Address>) -> Result<(), ConfigurableAccountError> {
        if self.owners.is_empty() {
            return Err(ConfigurableAccountError::EmptyOwners);
        }
        if self.owners.len() > MAX_CONFIGURABLE_ACCOUNT_OWNERS {
            return Err(ConfigurableAccountError::TooManyOwners);
        }
        if self.threshold == 0 {
            return Err(ConfigurableAccountError::ZeroThreshold);
        }
        for owner in &self.owners {
            if owner.owner.is_zero() {
                return Err(ConfigurableAccountError::ZeroOwner);
            }
            if self.version == 0 && account == Some(owner.owner) {
                return Err(ConfigurableAccountError::AccountIsOwner);
            }
        }
        if self.owners.iter().any(|owner| owner.weight == 0) {
            return Err(ConfigurableAccountError::ZeroWeight);
        }
        if self
            .owners
            .windows(2)
            .any(|pair| pair[0].owner >= pair[1].owner)
        {
            if self.owners.iter().enumerate().any(|(index, owner)| {
                self.owners[..index]
                    .iter()
                    .any(|previous| previous.owner == owner.owner)
            }) {
                return Err(ConfigurableAccountError::DuplicateOwner);
            }
            return Err(ConfigurableAccountError::OwnersNotAscending);
        }
        self.owners
            .iter()
            .try_fold(0u8, |total, owner| total.checked_add(owner.weight))
            .ok_or(ConfigurableAccountError::TotalWeightExceedsMax)?;
        let mut largest = [0u8; MAX_CONFIGURABLE_ACCOUNT_SIGNATURES];
        for owner in &self.owners {
            if owner.weight > largest[0] {
                largest[0] = owner.weight;
                largest.sort_unstable();
            }
        }
        let reachable: u16 = largest.into_iter().map(u16::from).sum();
        if u16::from(self.threshold) > reachable {
            return Err(ConfigurableAccountError::ThresholdExceedsWeight);
        }
        Ok(())
    }
}

/// Digest configurable account owners sign for `inner_digest` (here a
/// TIP-1034 voucher digest): `keccak256("tempo:configurable-account:signature"
/// || inner_digest || account || version as u64 big-endian)`.
pub fn configurable_account_digest(inner_digest: B256, account: Address, version: u64) -> B256 {
    let mut input = Vec::with_capacity(CONFIGURABLE_ACCOUNT_SIGNATURE_DOMAIN.len() + 32 + 20 + 8);
    input.extend_from_slice(CONFIGURABLE_ACCOUNT_SIGNATURE_DOMAIN);
    input.extend_from_slice(inner_digest.as_slice());
    input.extend_from_slice(account.as_slice());
    input.extend_from_slice(&version.to_be_bytes());
    keccak256(input)
}

/// A `0x05` configurable account signature: `0x05 || rlp([account, [salt,
/// version, threshold, [[owner, weight]...]], [approval...]])`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurableAccountSignature {
    account: Address,
    config: ConfigurableAccountConfig,
    signatures: Vec<PrimitiveSignature>,
}

impl ConfigurableAccountSignature {
    /// Build a signature, checking its shape.
    pub fn try_new(
        account: Address,
        config: ConfigurableAccountConfig,
        signatures: Vec<PrimitiveSignature>,
    ) -> Result<Self, ConfigurableAccountError> {
        if account.is_zero() {
            return Err(ConfigurableAccountError::ZeroAccount);
        }
        config.validate_inner(Some(account))?;
        if signatures.is_empty() {
            return Err(ConfigurableAccountError::EmptySignatures);
        }
        if signatures.len() > MAX_CONFIGURABLE_ACCOUNT_SIGNATURES {
            return Err(ConfigurableAccountError::TooManySignatures);
        }
        if signatures.iter().any(|signature| {
            signature.to_bytes().len() > MAX_CONFIGURABLE_ACCOUNT_OWNER_SIGNATURE_BYTES
        }) {
            return Err(ConfigurableAccountError::OwnerSignatureTooLarge);
        }
        Ok(Self {
            account,
            config,
            signatures,
        })
    }

    /// Account the signature signs for.
    pub const fn account(&self) -> Address {
        self.account
    }

    /// Configuration the signature presents.
    pub const fn config(&self) -> &ConfigurableAccountConfig {
        &self.config
    }

    /// Owner approvals, in ascending owner order.
    pub fn signatures(&self) -> &[PrimitiveSignature] {
        &self.signatures
    }

    /// Commitment of the presented configuration.
    pub fn config_commitment(&self) -> B256 {
        self.config.commitment_unchecked()
    }

    /// Check the presented configuration against the account's commitment:
    /// a nonzero `stored` commitment must equal it; a zero one accepts only
    /// the version-0 configuration the account's address derives from.
    pub fn validate_account_commitment(&self, stored: B256) -> bool {
        let actual = self.config_commitment();
        if actual.is_zero() || (!stored.is_zero() && stored != actual) {
            return false;
        }
        if stored.is_zero() {
            return self.config.version == 0
                && self.config.account_address_unchecked() == self.account;
        }
        true
    }

    /// Whether the approvals recover to owners, in strictly ascending order,
    /// whose weights reach the threshold with no approval to spare.
    pub fn verify_approvals(&self, inner_digest: B256) -> bool {
        let digest = configurable_account_digest(inner_digest, self.account, self.config.version);
        let threshold = u16::from(self.config.threshold);
        let mut previous: Option<Address> = None;
        let mut weight = 0u16;
        let mut min_weight = u8::MAX;
        for (index, approval) in self.signatures.iter().enumerate() {
            let Ok(owner) = TempoSignature::Primitive(approval.clone()).recover_signer(&digest)
            else {
                return false;
            };
            let Some(owner_weight) = self.config.owner_weight(owner) else {
                return false;
            };
            if previous.is_some_and(|previous| previous >= owner) {
                return false;
            }
            previous = Some(owner);
            weight += u16::from(owner_weight);
            min_weight = min_weight.min(owner_weight);
            if weight >= threshold && index + 1 != self.signatures.len() {
                return false;
            }
        }
        // Dropping the lightest approval must fall below the threshold, so no
        // approval can be stripped from a valid quorum.
        weight >= threshold && weight < threshold + u16::from(min_weight)
    }

    /// Encode as `0x05 || rlp(...)`.
    pub fn to_bytes(&self) -> Bytes {
        let mut out = Vec::with_capacity(1 + list_length(self.payload_length()));
        out.push(SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT);
        self.rlp_encode(&mut out);
        Bytes::from(out)
    }

    /// Decode canonical `0x05 || rlp(...)` bytes. Returns `None` for any
    /// other signature type.
    pub fn from_bytes(bytes: &[u8]) -> Option<Result<Self, ConfigurableAccountError>> {
        let (&type_byte, rest) = bytes.split_first()?;
        if type_byte != SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT {
            return None;
        }
        Some(Self::decode_rlp(rest))
    }

    fn decode_rlp(mut buf: &[u8]) -> Result<Self, ConfigurableAccountError> {
        let invalid = |_| ConfigurableAccountError::InvalidEncoding;
        let mut payload = list_payload(&mut buf).map_err(invalid)?;
        if !buf.is_empty() {
            return Err(ConfigurableAccountError::InvalidEncoding);
        }
        let account = Address::decode(&mut payload).map_err(invalid)?;
        let mut config_payload = list_payload(&mut payload).map_err(invalid)?;
        let salt = B256::decode(&mut config_payload).map_err(invalid)?;
        let version = u64::decode(&mut config_payload).map_err(invalid)?;
        let threshold = u8::decode(&mut config_payload).map_err(invalid)?;
        let mut owners_payload = list_payload(&mut config_payload).map_err(invalid)?;
        let mut owners = Vec::new();
        while !owners_payload.is_empty() {
            if owners.len() >= MAX_CONFIGURABLE_ACCOUNT_OWNERS {
                return Err(ConfigurableAccountError::TooManyOwners);
            }
            let mut owner_payload = list_payload(&mut owners_payload).map_err(invalid)?;
            let owner = Address::decode(&mut owner_payload).map_err(invalid)?;
            let weight = u8::decode(&mut owner_payload).map_err(invalid)?;
            if !owner_payload.is_empty() {
                return Err(ConfigurableAccountError::InvalidEncoding);
            }
            owners.push(ConfigurableAccountOwner { owner, weight });
        }
        if !config_payload.is_empty() {
            return Err(ConfigurableAccountError::InvalidEncoding);
        }
        let mut signatures_payload = list_payload(&mut payload).map_err(invalid)?;
        let mut signatures = Vec::new();
        while !signatures_payload.is_empty() {
            if signatures.len() >= MAX_CONFIGURABLE_ACCOUNT_SIGNATURES {
                return Err(ConfigurableAccountError::TooManySignatures);
            }
            let raw = Header::decode_bytes(&mut signatures_payload, false).map_err(invalid)?;
            let signature = PrimitiveSignature::from_bytes(raw)
                .map_err(|_| ConfigurableAccountError::InvalidEncoding)?;
            if signature.to_bytes().as_ref() != raw {
                return Err(ConfigurableAccountError::InvalidEncoding);
            }
            signatures.push(signature);
        }
        if !payload.is_empty() {
            return Err(ConfigurableAccountError::InvalidEncoding);
        }
        Self::try_new(
            account,
            ConfigurableAccountConfig {
                salt,
                version,
                threshold,
                owners,
            },
            signatures,
        )
    }

    fn owners_payload_length(&self) -> usize {
        self.config
            .owners
            .iter()
            .map(|owner| list_length(owner.owner.length() + owner.weight.length()))
            .sum()
    }

    fn config_payload_length(&self) -> usize {
        self.config.salt.length()
            + self.config.version.length()
            + self.config.threshold.length()
            + list_length(self.owners_payload_length())
    }

    fn signatures_payload_length(&self) -> usize {
        self.signatures
            .iter()
            .map(|signature| signature.to_bytes().as_ref().length())
            .sum()
    }

    fn payload_length(&self) -> usize {
        self.account.length()
            + list_length(self.config_payload_length())
            + list_length(self.signatures_payload_length())
    }

    fn rlp_encode(&self, out: &mut Vec<u8>) {
        list_header(self.payload_length()).encode(out);
        self.account.encode(out);
        list_header(self.config_payload_length()).encode(out);
        self.config.salt.encode(out);
        self.config.version.encode(out);
        self.config.threshold.encode(out);
        list_header(self.owners_payload_length()).encode(out);
        for owner in &self.config.owners {
            list_header(owner.owner.length() + owner.weight.length()).encode(out);
            owner.owner.encode(out);
            owner.weight.encode(out);
        }
        list_header(self.signatures_payload_length()).encode(out);
        for signature in &self.signatures {
            signature.to_bytes().as_ref().encode(out);
        }
    }
}

const fn list_header(payload_length: usize) -> Header {
    Header {
        list: true,
        payload_length,
    }
}

fn list_length(payload_length: usize) -> usize {
    list_header(payload_length).length_with_payload()
}

fn list_payload<'a>(buf: &mut &'a [u8]) -> alloy::rlp::Result<&'a [u8]> {
    let header = Header::decode(buf)?;
    if !header.list {
        return Err(alloy::rlp::Error::UnexpectedString);
    }
    if buf.len() < header.payload_length {
        return Err(alloy::rlp::Error::InputTooShort);
    }
    let (payload, rest) = buf.split_at(header.payload_length);
    *buf = rest;
    Ok(payload)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;

    /// `count` random owners in ascending address order.
    pub(crate) fn owners(count: usize) -> Vec<PrivateKeySigner> {
        let mut signers: Vec<_> = (0..count).map(|_| PrivateKeySigner::random()).collect();
        signers.sort_by_key(|signer| signer.address());
        signers
    }

    /// A version-0 configuration of `signers` with weight 1 each.
    pub(crate) fn config(signers: &[PrivateKeySigner], threshold: u8) -> ConfigurableAccountConfig {
        ConfigurableAccountConfig {
            salt: B256::repeat_byte(0x11),
            version: 0,
            threshold,
            owners: signers
                .iter()
                .map(|signer| ConfigurableAccountOwner {
                    owner: signer.address(),
                    weight: 1,
                })
                .collect(),
        }
    }

    /// A `0x05` signature of `inner` approved by `signers`, in that order.
    pub(crate) fn sign(
        signers: &[&PrivateKeySigner],
        account: Address,
        config: &ConfigurableAccountConfig,
        inner: B256,
    ) -> ConfigurableAccountSignature {
        let digest = configurable_account_digest(inner, account, config.version);
        let approvals = signers
            .iter()
            .map(|signer| PrimitiveSignature::Secp256k1(signer.sign_hash_sync(&digest).unwrap()))
            .collect();
        ConfigurableAccountSignature::try_new(account, config.clone(), approvals).unwrap()
    }

    #[test]
    fn digest_matches_preimage_layout() {
        let inner = B256::repeat_byte(0xaa);
        let account = Address::repeat_byte(0xbb);
        let mut preimage = b"tempo:configurable-account:signature".to_vec();
        preimage.extend_from_slice(inner.as_slice());
        preimage.extend_from_slice(account.as_slice());
        preimage.extend_from_slice(&7u64.to_be_bytes());
        assert_eq!(
            configurable_account_digest(inner, account, 7),
            keccak256(preimage)
        );
    }

    #[test]
    fn round_trips_and_verifies_quorum() {
        let signers = owners(3);
        let config = config(&signers, 2);
        let account = config.account_address().unwrap();
        let inner = B256::repeat_byte(0x42);
        let signature = sign(&[&signers[0], &signers[2]], account, &config, inner);
        let bytes = signature.to_bytes();
        assert_eq!(bytes[0], SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT);
        let decoded = ConfigurableAccountSignature::from_bytes(&bytes)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, signature);
        assert!(decoded.verify_approvals(inner));
        assert!(!decoded.verify_approvals(B256::repeat_byte(0x43)));
        assert!(decoded.validate_account_commitment(B256::ZERO));
        assert!(decoded.validate_account_commitment(config.commitment().unwrap()));
        assert!(!decoded.validate_account_commitment(B256::repeat_byte(1)));

        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(ConfigurableAccountSignature::from_bytes(&trailing)
            .unwrap()
            .is_err());
        assert!(ConfigurableAccountSignature::from_bytes(&[0x01, 0x02]).is_none());
    }

    #[test]
    fn rejects_unordered_short_or_excess_approvals() {
        let signers = owners(3);
        let config = config(&signers, 2);
        let account = config.account_address().unwrap();
        let inner = B256::repeat_byte(0x42);
        let check = |chosen: &[&PrivateKeySigner]| {
            sign(chosen, account, &config, inner).verify_approvals(inner)
        };
        assert!(check(&[&signers[0], &signers[1]]));
        assert!(!check(&[&signers[1], &signers[0]]));
        assert!(!check(&[&signers[0]]));
        assert!(!check(&[&signers[0], &signers[1], &signers[2]]));
    }

    #[test]
    fn zero_commitment_needs_version_zero_derivation() {
        let signers = owners(1);
        let mut config = config(&signers, 1);
        let account = config.account_address().unwrap();
        let inner = B256::repeat_byte(0x42);
        let other = Address::repeat_byte(0x77);
        let wrong_account = sign(&[&signers[0]], other, &config, inner);
        assert!(wrong_account.verify_approvals(inner));
        assert!(!wrong_account.validate_account_commitment(B256::ZERO));

        config.version = 1;
        let rotated = sign(&[&signers[0]], account, &config, inner);
        assert!(!rotated.validate_account_commitment(B256::ZERO));
        assert!(rotated.validate_account_commitment(config.commitment().unwrap()));
    }

    #[test]
    fn config_validation_matches_tempo() {
        let signers = owners(2);
        let mut reversed = config(&signers, 1);
        reversed.owners.reverse();
        assert_eq!(
            reversed.validate(),
            Err(ConfigurableAccountError::OwnersNotAscending)
        );
        let mut duplicate = config(&signers, 1);
        duplicate.owners[1] = duplicate.owners[0];
        assert_eq!(
            duplicate.validate(),
            Err(ConfigurableAccountError::DuplicateOwner)
        );
        assert_eq!(
            config(&signers, 3).validate(),
            Err(ConfigurableAccountError::ThresholdExceedsWeight)
        );
    }
}
