//! EIP-712 voucher signature verification for stream payment channels.

use alloy::primitives::{Address, B256};
use alloy::signers::Signature;
use alloy::sol;
use alloy::sol_types::{eip712_domain, SolStruct};

sol! {
    #[derive(Default)]
    struct Voucher {
        bytes32 channelId;
        uint128 cumulativeAmount;
    }
}

/// Recover the signer address from an EIP-712 voucher signature.
pub fn recover_voucher_signer(
    channel_id: B256,
    cumulative_amount: u128,
    escrow_contract: Address,
    chain_id: u64,
    signature_hex: &str,
) -> Result<Address, String> {
    let domain = eip712_domain! {
        name: "Tempo Stream Channel",
        version: "1",
        chain_id: chain_id,
        verifying_contract: escrow_contract,
    };

    let voucher = Voucher {
        channelId: channel_id,
        cumulativeAmount: cumulative_amount,
    };

    let signing_hash = voucher.eip712_signing_hash(&domain);

    let sig_hex = signature_hex.strip_prefix("0x").unwrap_or(signature_hex);
    let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("invalid signature hex: {}", e))?;

    if sig_bytes.len() != 65 {
        return Err(format!(
            "expected 65 byte signature, got {}",
            sig_bytes.len()
        ));
    }

    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| format!("invalid signature: {}", e))?;

    let recovered = signature
        .recover_address_from_prehash(&signing_hash)
        .map_err(|e| format!("failed to recover signer: {}", e))?;

    Ok(recovered)
}

/// Verify that a voucher signature was created by the expected signer.
pub fn verify_voucher_signature(
    channel_id: B256,
    cumulative_amount: u128,
    escrow_contract: Address,
    chain_id: u64,
    signature_hex: &str,
    expected_signer: Address,
) -> Result<(), String> {
    let recovered = recover_voucher_signer(
        channel_id,
        cumulative_amount,
        escrow_contract,
        chain_id,
        signature_hex,
    )?;

    if recovered != expected_signer {
        return Err(format!(
            "signature signer mismatch: recovered {:#x}, expected {:#x}",
            recovered, expected_signer
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;

    fn sign_test_voucher(
        signer: &PrivateKeySigner,
        channel_id: B256,
        cumulative_amount: u128,
        escrow_contract: Address,
        chain_id: u64,
    ) -> String {
        let domain = eip712_domain! {
            name: "Tempo Stream Channel",
            version: "1",
            chain_id: chain_id,
            verifying_contract: escrow_contract,
        };

        let voucher = Voucher {
            channelId: channel_id,
            cumulativeAmount: cumulative_amount,
        };

        let signing_hash = voucher.eip712_signing_hash(&domain);
        let sig = signer.sign_hash_sync(&signing_hash).unwrap();
        format!("0x{}", hex::encode(sig.as_bytes()))
    }

    #[test]
    fn test_recover_voucher_signer() {
        let signer: PrivateKeySigner =
            "0x1234567890123456789012345678901234567890123456789012345678901234"
                .parse()
                .unwrap();
        let escrow: Address = "0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70"
            .parse()
            .unwrap();
        let channel_id = B256::repeat_byte(0x01);

        let sig = sign_test_voucher(&signer, channel_id, 1000, escrow, 42431);
        let recovered = recover_voucher_signer(channel_id, 1000, escrow, 42431, &sig).unwrap();
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn test_verify_voucher_signature_success() {
        let signer: PrivateKeySigner =
            "0x1234567890123456789012345678901234567890123456789012345678901234"
                .parse()
                .unwrap();
        let escrow: Address = "0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70"
            .parse()
            .unwrap();
        let channel_id = B256::repeat_byte(0x01);

        let sig = sign_test_voucher(&signer, channel_id, 5000, escrow, 42431);
        let result =
            verify_voucher_signature(channel_id, 5000, escrow, 42431, &sig, signer.address());
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_voucher_signature_wrong_signer() {
        let signer: PrivateKeySigner =
            "0x1234567890123456789012345678901234567890123456789012345678901234"
                .parse()
                .unwrap();
        let other: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2"
            .parse()
            .unwrap();
        let escrow: Address = "0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70"
            .parse()
            .unwrap();
        let channel_id = B256::repeat_byte(0x01);

        let sig = sign_test_voucher(&signer, channel_id, 5000, escrow, 42431);
        let result = verify_voucher_signature(channel_id, 5000, escrow, 42431, &sig, other);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("mismatch"));
    }

    #[test]
    fn test_verify_voucher_wrong_amount_fails() {
        let signer: PrivateKeySigner =
            "0x1234567890123456789012345678901234567890123456789012345678901234"
                .parse()
                .unwrap();
        let escrow: Address = "0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70"
            .parse()
            .unwrap();
        let channel_id = B256::repeat_byte(0x01);

        let sig = sign_test_voucher(&signer, channel_id, 5000, escrow, 42431);
        let result =
            verify_voucher_signature(channel_id, 9999, escrow, 42431, &sig, signer.address());
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_voucher_wrong_chain_id_fails() {
        let signer: PrivateKeySigner =
            "0x1234567890123456789012345678901234567890123456789012345678901234"
                .parse()
                .unwrap();
        let escrow: Address = "0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70"
            .parse()
            .unwrap();
        let channel_id = B256::repeat_byte(0x01);

        let sig = sign_test_voucher(&signer, channel_id, 5000, escrow, 42431);
        let result =
            verify_voucher_signature(channel_id, 5000, escrow, 4217, &sig, signer.address());
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_signature_hex() {
        let escrow: Address = "0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70"
            .parse()
            .unwrap();
        let result = recover_voucher_signer(B256::ZERO, 1000, escrow, 42431, "0xGGGG");
        assert!(result.is_err());
    }

    #[test]
    fn test_short_signature() {
        let escrow: Address = "0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70"
            .parse()
            .unwrap();
        let result = recover_voucher_signer(B256::ZERO, 1000, escrow, 42431, "0xabcdef");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("65 byte"));
    }
}
