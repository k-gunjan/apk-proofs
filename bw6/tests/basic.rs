mod helper;

fn main() {
    let validators = helper::parse_args_or(255, "basic");
    println!(
        "Running test for the 'basic' scheme for {} validators",
        validators
    );
    apk_proofs::test_helpers::test_simple_scheme(validators);
}
