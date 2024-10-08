#![no_main]

use aptos_lc_core::crypto::hash::{CryptoHash, HashValue};
use aptos_lc_core::merkle::sparse_proof::SparseMerkleProof;
use aptos_lc_core::merkle::transaction_proof::TransactionAccumulatorProof;
use aptos_lc_core::types::ledger_info::LedgerInfoWithSignatures;
use aptos_lc_core::types::transaction::TransactionInfo;
use aptos_lc_core::types::validator::ValidatorVerifier;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let sparse_merkle_proof_bytes = sp1_zkvm::io::read_vec();
    let key: [u8; 32] = sp1_zkvm::io::read();
    let leaf_value_hash: [u8; 32] = sp1_zkvm::io::read();

    let transaction_bytes = sp1_zkvm::io::read_vec();
    let transaction_index: u64 = sp1_zkvm::io::read();
    let transaction_proof = sp1_zkvm::io::read_vec();
    let ledger_info_bytes = sp1_zkvm::io::read_vec();

    let verified_validator_verifier = sp1_zkvm::io::read_vec();

    let validator_verifier = ValidatorVerifier::from_bytes(&verified_validator_verifier)
        .expect("validator_verifier: could not create ValidatorVerifier from bytes");

    // Verify transaction inclusion in the LedgerInfoWithSignatures
    let transaction = TransactionInfo::from_bytes(&transaction_bytes)
        .expect("from_bytes: could not deserialize TransactionInfo");
    let transaction_hash = transaction.hash();
    let transaction_proof = TransactionAccumulatorProof::from_bytes(&transaction_proof)
        .expect("from_bytes: could not deserialize TransactionAccumulatorProof");
    let latest_li = LedgerInfoWithSignatures::from_bytes(&ledger_info_bytes)
        .expect("from_bytes: could not deserialize LedgerInfo");
    let expected_root_hash = latest_li.ledger_info().transaction_accumulator_hash();

    transaction_proof
        .verify(expected_root_hash, transaction_hash, transaction_index)
        .expect("verify: could not verify proof");
    latest_li
        .verify_signatures(&validator_verifier)
        .expect("verify_signatures: could not verify signatures");
    let sparse_merkle_proof = SparseMerkleProof::from_bytes(&sparse_merkle_proof_bytes)
        .expect("from_bytes: could not deserialize SparseMerkleProof");
    let sparse_expected_root_hash = transaction
        .state_checkpoint()
        .expect("state_checkpoint: could not get state checkpoint");
    let reconstructed_root_hash = sparse_merkle_proof
        .verify_by_hash(
            sparse_expected_root_hash,
            HashValue::from_slice(key).expect("key: could not use input to create HashValue"),
            HashValue::from_slice(leaf_value_hash)
                .expect("leaf_value_hash: could not use input to create HashValue"),
        )
        .expect("verify_by_hash: could not verify proof");

    sp1_zkvm::io::commit(validator_verifier.hash().as_ref());

    // Commit the state root hash
    sp1_zkvm::io::commit(reconstructed_root_hash.as_ref());

    // Commit current block id
    let block_hash = latest_li.ledger_info().block_id();
    sp1_zkvm::io::commit(block_hash.as_ref());

    // Commit key
    sp1_zkvm::io::commit(&key);

    // Commit leaf value hash
    sp1_zkvm::io::commit(&leaf_value_hash);
}
