mod helper;

fn main() {
    let validators = helper::parse_args_or(255, "counting");
    println!(
        "Running test for the 'counting' scheme for {} validators",
        validators
    );
    apk_proofs::test_helpers::test_counting_scheme(validators);
}
