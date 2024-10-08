use sp1_helper::build_program_with_args;

fn main() {
    build_program_with_args("../programs/epoch-change", Default::default());
    build_program_with_args("../programs/inclusion", Default::default())

}
