use getset::Getters;
use serde::{Deserialize, Serialize};
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};
use crate::error::LightClientError;

pub const INCLUSION_ELF: &[u8] = include_bytes!("../../programs/inclusion/elf/riscv32im-succinct-zkvm-elf");

#[derive(Clone, Debug, Getters, Serialize, Deserialize)]
#[getset(get = "pub")]
pub struct SparseMerkleProofAssets {
    sparse_merkle_proof: Vec<u8>,
    leaf_key: [u8; 32],
    leaf_hash: [u8; 32],
}

impl SparseMerkleProofAssets {
    pub const fn new(
        sparse_merkle_proof: Vec<u8>,
        leaf_key: [u8; 32],
        leaf_hash: [u8; 32],
    ) -> SparseMerkleProofAssets {
        SparseMerkleProofAssets {
            sparse_merkle_proof,
            leaf_key,
            leaf_hash,
        }
    }
}

#[derive(Clone, Debug, Getters, Serialize, Deserialize)]
#[getset(get = "pub")]
pub struct TransactionProofAssets {
    transaction: Vec<u8>,
    transaction_index: u64,
    transaction_proof: Vec<u8>,
    latest_li: Vec<u8>,
}

impl TransactionProofAssets {
    pub const fn new(
        transaction: Vec<u8>,
        transaction_index: u64,
        transaction_proof: Vec<u8>,
        latest_li: Vec<u8>,
    ) -> TransactionProofAssets {
        TransactionProofAssets {
            transaction,
            transaction_index,
            transaction_proof,
            latest_li,
        }
    }
}

#[derive(Clone, Debug, Getters, Serialize, Deserialize)]
#[getset(get = "pub")]
pub struct ValidatorVerifierAssets {
    validator_verifier: Vec<u8>,
}

impl ValidatorVerifierAssets {
    pub const fn new(validator_verifier: Vec<u8>) -> ValidatorVerifierAssets {
        ValidatorVerifierAssets { validator_verifier }
    }
}


#[inline]
pub fn generate_keys(client: &ProverClient) -> (SP1ProvingKey, SP1VerifyingKey) {
    client.setup(INCLUSION_ELF)
}

#[allow(dead_code)]
struct InclusionOutput {
    validator_verifier_hash: [u8; 32],
    state_hash: [u8; 32],
    block_hash: [u8; 32],
    key: [u8; 32],
    value: [u8; 32],
}

pub fn generate_stdin(
    sparse_merkle_proof_assets: &SparseMerkleProofAssets,
    transaction_proof_assets: &TransactionProofAssets,
    validator_verifier_assets: &ValidatorVerifierAssets,
) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();

    // Validator verifier: Writes validator verifier data for proof validation.
    stdin.write_vec(sparse_merkle_proof_assets.sparse_merkle_proof.clone());
    stdin.write(&sparse_merkle_proof_assets.leaf_key);
    stdin.write(&sparse_merkle_proof_assets.leaf_hash);

    // Tx inclusion input
    stdin.write_vec(transaction_proof_assets.transaction.clone());
    stdin.write(&transaction_proof_assets.transaction_index);
    stdin.write_vec(transaction_proof_assets.transaction_proof.clone());
    stdin.write_vec(transaction_proof_assets.latest_li.clone());

    // Validator verifier
    stdin.write_vec(validator_verifier_assets.validator_verifier.clone());

    stdin
}

#[allow(dead_code)]
fn prove_inclusion(
    client: &ProverClient,
    sparse_merkle_proof_assets: &SparseMerkleProofAssets,
    transaction_proof_assets: &TransactionProofAssets,
    validator_verifier_assets: &ValidatorVerifierAssets,
) -> Result<(SP1ProofWithPublicValues, InclusionOutput), LightClientError> {
    sp1_sdk::utils::setup_logger();

    let stdin = generate_stdin(
        sparse_merkle_proof_assets,
        transaction_proof_assets,
        validator_verifier_assets,
    );
    let (pk, _) = generate_keys(client);

    let mut proof =
        client
            .prove(&pk, stdin)
            .run()
            .map_err(|err| LightClientError::ProvingError {
                program: "prove-merkle-inclusion".to_string(),
                source: err.into(),
            })?;

    // Read output.
    let validator_verifier_hash: [u8; 32] = proof.public_values.read();
    let state_hash: [u8; 32]  = proof.public_values.read();
    let block_hash: [u8; 32]  = proof.public_values.read();
    let key: [u8; 32]  = proof.public_values.read();
    let value: [u8; 32]  = proof.public_values.read();

    Ok((
        proof,
        InclusionOutput {
            validator_verifier_hash,
            state_hash,
            block_hash,
            key,
            value,
        },
    ))
}

