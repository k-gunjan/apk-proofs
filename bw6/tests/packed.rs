mod helper;

fn main() {
    let validators = helper::parse_args_or(255, "packed");
    println!(
        "Running test for the 'packed' scheme for {} validators",
        validators
    );
    apk_proofs::test_helpers::test_packed_scheme(validators);
}
