use std::time::{Duration, Instant};
use clap::Parser;
use serde::Serialize;
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1Stdin};

use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
use aptos_lc_core::crypto::hash::CryptoHash;
use aptos_lc_core::types::ledger_info::LedgerInfoWithSignatures;
use aptos_lc_core::types::trusted_state::TrustedState;
use aptos_lc_core::types::validator::ValidatorVerifier;
use aptos_lc_script::inclusion::{
    SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets,
};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const INCLUSION_ELF: &[u8] = include_bytes!("../../../programs/inclusion/elf/riscv32im-succinct-zkvm-elf");


const NBR_LEAVES: [usize; 5] = [32, 128, 2048, 8192, 32768];
const NBR_VALIDATORS: usize = 130;
const AVERAGE_SIGNERS_NBR: usize = 95;

struct ProvingAssets {
    sparse_merkle_proof_assets: SparseMerkleProofAssets,
    transaction_proof_assets: TransactionProofAssets,
    validator_verifier_assets: ValidatorVerifierAssets,
    state_checkpoint_hash: [u8; 32],
}

impl ProvingAssets {
    fn from_nbr_leaves(nbr_leaves: usize) -> Self {
        let mut aptos_wrapper =
            AptosWrapper::new(nbr_leaves, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR).unwrap();
        aptos_wrapper.generate_traffic().unwrap();

        let trusted_state = bcs::to_bytes(aptos_wrapper.trusted_state()).unwrap();
        let validator_verifier = match TrustedState::from_bytes(&trusted_state).unwrap() {
            TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().clone(),
            _ => panic!("expected epoch state"),
        };

        let proof_assets = aptos_wrapper
            .get_latest_proof_account(nbr_leaves - 1)
            .unwrap();

        let sparse_merkle_proof = bcs::to_bytes(proof_assets.state_proof()).unwrap();
        let key: [u8; 32] = *proof_assets.key().as_ref();
        let element_hash: [u8; 32] = *proof_assets.state_value_hash().unwrap().as_ref();

        let transaction = bcs::to_bytes(&proof_assets.transaction()).unwrap();
        let transaction_proof = bcs::to_bytes(&proof_assets.transaction_proof()).unwrap();
        let latest_li = aptos_wrapper.get_latest_li_bytes().unwrap();

        let sparse_merkle_proof_assets =
            SparseMerkleProofAssets::new(sparse_merkle_proof, key, element_hash);

        let state_checkpoint_hash = proof_assets
            .transaction()
            .ensure_state_checkpoint_hash()
            .unwrap();

        let transaction_proof_assets = TransactionProofAssets::new(
            transaction,
            *proof_assets.transaction_version(),
            transaction_proof,
            latest_li,
        );

        let validator_verifier_assets = ValidatorVerifierAssets::new(validator_verifier.to_bytes());

        Self {
            sparse_merkle_proof_assets,
            transaction_proof_assets,
            validator_verifier_assets,
            state_checkpoint_hash: *state_checkpoint_hash.as_ref(),
        }
    }

    fn prove(&self) -> SP1ProofWithPublicValues{
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();

        stdin.write_vec(self.sparse_merkle_proof_assets.sparse_merkle_proof().clone());
        stdin.write(self.sparse_merkle_proof_assets.leaf_key());
        stdin.write(self.sparse_merkle_proof_assets.leaf_hash());

        // Tx inclusion input: Writes transaction related data to stdin.
        stdin.write_vec(self.transaction_proof_assets.transaction().clone());
        stdin.write(self.transaction_proof_assets.transaction_index());
        stdin.write_vec(self.transaction_proof_assets.transaction_proof().clone());
        stdin.write_vec(self.transaction_proof_assets.latest_li().clone());

        // Validator verifier: Writes validator verifier data for proof validation.
        stdin.write_vec(self.validator_verifier_assets.validator_verifier().clone());

        let (pk, _) = client.setup(INCLUSION_ELF);
        let proof = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");
        proof
    }

    fn execute(&self) {
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(self.sparse_merkle_proof_assets.sparse_merkle_proof().clone());
        stdin.write(self.sparse_merkle_proof_assets.leaf_key());
        stdin.write(self.sparse_merkle_proof_assets.leaf_hash());

        // Tx inclusion input: Writes transaction related data to stdin.
        stdin.write_vec(self.transaction_proof_assets.transaction().clone());
        stdin.write(self.transaction_proof_assets.transaction_index());
        stdin.write_vec(self.transaction_proof_assets.transaction_proof().clone());
        stdin.write_vec(self.transaction_proof_assets.latest_li().clone());

        // Validator verifier: Writes validator verifier data for proof validation.
        stdin.write_vec(self.validator_verifier_assets.validator_verifier().clone());

        let (_, report) = client.execute(INCLUSION_ELF, stdin).run().unwrap();

        // Record the report.
        println!("Report: {}", report);
    }
}

#[derive(Serialize)]
struct Timings {
    nbr_leaves: usize,
    proving_time: u128,
    verifying_time: u128,
}

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

}


fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    for nbr_leaves in NBR_LEAVES {
        let proving_assets = ProvingAssets::from_nbr_leaves(nbr_leaves);
        if args.execute {
            proving_assets.execute();
        } else {

            let start_proving = Instant::now();
            let mut inclusion_proof = proving_assets.prove();
            let proving_time = start_proving.elapsed();

            // Verify the consistency of the validator verifier hash post-merkle proof.
            // This verifies the validator consistency required by P1.
            let prev_validator_verifier_hash: [u8; 32] = inclusion_proof.public_values.read();
            assert_eq!(
                &prev_validator_verifier_hash,
                ValidatorVerifier::from_bytes(
                    proving_assets
                        .validator_verifier_assets
                        .validator_verifier()
                )
                    .unwrap()
                    .hash()
                    .as_ref()
            );

            // Verify the consistency of the final merkle root hash computed
            // by the program against the expected one.
            // This verifies P3 out-of-circuit.
            let merkle_root_slice: [u8; 32] = inclusion_proof.public_values.read();
            assert_eq!(
                merkle_root_slice, proving_assets.state_checkpoint_hash,
                "Merkle root hash mismatch"
            );

            let block_hash: [u8; 32] = inclusion_proof.public_values.read();
            let lates_li = proving_assets.transaction_proof_assets.latest_li();
            let expected_block_id = LedgerInfoWithSignatures::from_bytes(lates_li)
                .unwrap()
                .ledger_info()
                .block_id();
            assert_eq!(
                block_hash.to_vec(),
                expected_block_id.to_vec(),
                "Block hash mismatch"
            );

            let key: [u8; 32] = inclusion_proof.public_values.read();
            assert_eq!(
                key.to_vec(),
                proving_assets.sparse_merkle_proof_assets.leaf_key(),
                "Merkle tree key mismatch"
            );

            let value: [u8; 32] = inclusion_proof.public_values.read();
            assert_eq!(
                value.to_vec(),
                proving_assets.sparse_merkle_proof_assets.leaf_hash(),
                "Merkle tree value mismatch"
            );

            let timings = Timings {
                nbr_leaves,
                proving_time: proving_time.as_millis(),
                verifying_time: Duration::from_secs(0).as_millis(),
            };

            let json_output = serde_json::to_string(&timings).unwrap();
            println!("{}", json_output);
        }
    }
}
