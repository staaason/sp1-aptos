use sp1_sdk::{ProverClient, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};

pub const EPOCH_CHANGE_ELF: &[u8] = include_bytes!("../../programs/epoch-change/elf/riscv32im-succinct-zkvm-elf");


#[inline]
pub fn generate_keys(client: &ProverClient) -> (SP1ProvingKey, SP1VerifyingKey) {
    client.setup(EPOCH_CHANGE_ELF)
}

pub fn generate_stdin(current_trusted_state: &[u8], epoch_change_proof: &[u8]) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(current_trusted_state.to_vec());
    stdin.write_vec(epoch_change_proof.to_vec());
    stdin
}