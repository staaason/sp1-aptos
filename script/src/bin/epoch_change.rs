//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use clap::Parser;
use sp1_sdk::{ProverClient, SP1Stdin};

use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
use aptos_lc_core::crypto::hash::CryptoHash;
use aptos_lc_core::types::trusted_state::TrustedState;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const EPOCH_CHANGE_ELF: &[u8] = include_bytes!("../../../programs/epoch-change/elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    prove: bool,

}

const NBR_VALIDATORS: usize = 130;
const AVERAGE_SIGNERS_NBR: usize = 95;


struct ProvingAssets {
    trusted_state: Vec<u8>,
    validator_verifier_hash: Vec<u8>,
    epoch_change_proof: Vec<u8>,
}

impl ProvingAssets {
    /// Constructs a new instance of `ProvingAssets` by setting up the necessary state and proofs for the benchmark.
    fn new() -> Self {
        let mut aptos_wrapper = AptosWrapper::new(2, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR).unwrap();

        let trusted_state = bcs::to_bytes(aptos_wrapper.trusted_state()).unwrap();
        let validator_verifier_hash = match TrustedState::from_bytes(&trusted_state).unwrap() {
            TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().hash().to_vec(),
            _ => panic!("Expected epoch change for current trusted state"),
        };
        let trusted_state_version = *aptos_wrapper.current_version();

        aptos_wrapper.generate_traffic().unwrap();

        let state_proof = aptos_wrapper
            .new_state_proof(trusted_state_version)
            .unwrap();

        let epoch_change_proof = &bcs::to_bytes(state_proof.epoch_changes()).unwrap();

        Self {
            trusted_state,
            validator_verifier_hash,
            epoch_change_proof: epoch_change_proof.clone(),
        }
    }

    fn prove(&self){
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(self.trusted_state.clone());
        stdin.write_vec(self.epoch_change_proof.clone());
        let (pk, vk) = client.setup(EPOCH_CHANGE_ELF);
        let _ = client
            .prove(&pk, stdin)
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof!");
    }

    fn execute(&self) {
        let client = ProverClient::new();
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(self.trusted_state.clone());
        stdin.write_vec(self.epoch_change_proof.clone());

        let (_, report) = client.execute(EPOCH_CHANGE_ELF, stdin).run().unwrap();

        // Record the report.
        println!("Report: {}", report);
    }
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
    let proving_assets = ProvingAssets::new();


    if args.execute {
        // Execute the program
        proving_assets.execute();
    } else {
        proving_assets.prove();
    }
}
