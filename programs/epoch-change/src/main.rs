#![no_main]
sp1_zkvm::entrypoint!(main);


use aptos_lc_core::crypto::hash::CryptoHash;
use aptos_lc_core::types::trusted_state::{EpochChangeProof, TrustedState, TrustedStateChange};

pub fn main() {
    let trusted_state_bytes = sp1_zkvm::io::read_vec();
    let epoch_change_proof = sp1_zkvm::io::read_vec();
    let trusted_state = TrustedState::from_bytes(&trusted_state_bytes)
        .expect("TrustedState::from_bytes: could not create trusted state");
    let epoch_change_proof = EpochChangeProof::from_bytes(&epoch_change_proof)
        .expect("EpochChangeProof::from_bytes: could not create epoch change proof");
    let trusted_state_change = trusted_state
        .verify_and_ratchet_inner(&epoch_change_proof)
        .expect("TrustedState::verify_and_ratchet_inner: could not ratchet");
    let validator_verifier_hash = match trusted_state_change {
        TrustedStateChange::Epoch {
            latest_epoch_change_li,
            ..
        } => latest_epoch_change_li
            .ledger_info()
            .next_epoch_state()
            .expect("Expected epoch state")
            .verifier()
            .hash(),
        _ => panic!("Expected epoch change"),
    };
    let prev_epoch_validator_verifier_hash = match &trusted_state {
        TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().hash(),
        _ => panic!("Expected epoch change for current trusted state"),
    };


    sp1_zkvm::io::commit(prev_epoch_validator_verifier_hash.as_ref());
    sp1_zkvm::io::commit(validator_verifier_hash.as_ref());
}
