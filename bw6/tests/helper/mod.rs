use std::env;

/// Parses a validator-set size from the command line.
///
/// Deliberately not a `log_n`: what the caller has is a number of validators, and which
/// evaluation domain that implies is the configuration's business. On APK-381 no domain is a
/// power of two, so a logarithm would name nothing.
pub fn parse_args_or(default_validators: usize, scheme: &str) -> usize {
    match env::args().nth(1) {
        None => {
            println!(
                "VALIDATORS parameter is not provided, using the default.\n\
                 Run with '--test {} VALIDATORS', where VALIDATORS is the validator set size",
                scheme
            );
            default_validators
        }
        Some(arg) => arg.parse().unwrap_or_else(|_| panic!("{} is not a valid parameter", arg)),
    }
}
