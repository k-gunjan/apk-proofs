use std::cell::RefCell;
use std::collections::HashSet;

use ark_bls12_377::{G1Projective, G2Projective};
use ark_bw6_761::BW6_761;
use ark_ec::AffineRepr;
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use ark_std::{end_timer, start_timer};
use fflonk::pcs::kzg::params::{KzgCommitterKey, RawKzgVerifierKey};
use fflonk::pcs::kzg::urs::URS;
use fflonk::pcs::PcsParams;
use merlin::Transcript;
use rand::Rng;

use apk_proofs::bls::{PublicKey, SecretKey, Signature};
use apk_proofs::{
    hash_to_curve, setup, AccountablePublicInput, Bitmask, Keyset, KeysetCommitment, Prover,
    SimpleProof, Verifier,
};

// This example sketches the primary intended use case of the crate functionality:
// building communication-efficient light clients for blockchains.

// Here we model a blockchain as a set of validators who are responsible for signing for the chain events.
// The validator set changes in periods of time called 'eras'. Common assumptions is that within an era,
// only a fraction of validators in the set is malicious/unresponsive.

// Light client is a resource-constrained blockchain client (think a mobile app or better an Ethereum smart contract),
// that is interested in some of the chain events, but is not able to follow the chain itself.
// Instead it relies on a helper node that provides cryptographic proofs of the events requested by the client
// and doesn't need to be trusted.

// An example of such a proof could be a collection of signatures on the event from the relevant validator set,
// but it would require the client to know all the validators' public keys, that is inefficient.
// Neither knowing the aggregate public key of the validator set helps, as some of the individual signatures may be missing
// (due to unresponsive/malicious/deluded validators).

// The crate suggests succinct proofs of the public key being an aggregate public key of a subset of the validators set.
// The whole validator set is identified by a short commitment to it, and the subset is identified by the bitmask.
// This effectively gives an accountable subset signature with the commitment being a public key.

// The fundamental type of event a light client is interested in is the validator set change.
// Given it knows the (short commitment to) recent validator set, it can process signatures (proofs)
// of the other events (like a block finality) in the same way.

// Light client's state is initialized with a commitment 'C0' to the ('genesis') validator set of the era #0
// (and some technical stuff, like public parameters).

// When an era (tautologically, a validator set) changes, a helper provides:
// 1. the commitment 'C1' to the new validator set,
// 2. an aggregate signature 'asig0' of a subset of validators of the previous era on the new commitment 'C1',
// 3. an aggregate public key 'apk0' of this subset of validators,
// 4. a bitmask 'b0' identifying this subset in the whole set of the validators of the previous era, and
// 5. a proof 'p0', that attests that the key 'apk0' is indeed the aggregate public key of a subset identified by 'b0'
//                  of the set of the validators, identified by the commitment 'C0', of the previous era.
// All together this is ('C1', 'asig0', 'apk0', 'b0', 'p0').

// The light client:
// 1. makes sure that the key 'apk0' is correct by verifying the proof 'p0':
//    apk_verify('apk0', 'b0', 'C0'; 'p0') == true
// 2. verifies the aggregate signature 'asig0' agains the key 'apk0':
//    bls_verify('asig0', 'apk0', 'C1') == true
// 3. If both checks passed and the bitmask contains enough (say, >2/3 of) signers,
//    updates its state to the new commitment 'C1'.

#[derive(Clone)]
struct Validator(SecretKey);

struct Approval {
    comm: KeysetCommitment,
    sig: Signature,
    pk: PublicKey,
}

thread_local! {
    static CACHE: RefCell<Option<KeysetCommitment>> = RefCell::new(None);
}

fn new_era() {
    CACHE.with(|cell| {
        cell.replace(None);
    });
}

fn get_keyset_commitment<F>(f: F) -> KeysetCommitment
where
    F: FnOnce() -> KeysetCommitment,
{
    CACHE.with(|cell| {
        let mut cell = cell.borrow_mut();
        let old_opt = cell.as_ref();
        match old_opt {
            None => {
                let new_val = f();
                let new_opt = Some(new_val.clone());
                *cell = new_opt;
                new_val
            }
            Some(val) => val.clone(),
        }
    })
}

impl Validator {
    fn new<R: Rng>(rng: &mut R) -> Self {
        Self(SecretKey::new(rng))
    }

    fn public_key(&self) -> PublicKey {
        (&self.0).into()
    }

    fn approve(
        &self,
        new_validator_set: &ValidatorSet,
        kzg_pk: &KzgCommitterKey<ark_bw6_761::G1Affine>,
    ) -> Approval {
        // Computing the commitment to the new validator set is a time consuming operation.
        // In real-world deployments it is run by each validator, hence in parallel.
        // We model that by sharing the commitment generated by the first validator among others.
        let new_validator_set_commitment = get_keyset_commitment(|| {
            Keyset::new(new_validator_set.raw_public_keys()).commit(kzg_pk)
        });
        let message = hash_commitment(&new_validator_set_commitment);
        Approval {
            comm: new_validator_set_commitment,
            sig: self.0.sign(&message), //TODO: signing is also done in parallel
            pk: self.public_key(),
        }
    }
}

#[derive(Clone)]
struct ValidatorSet {
    validators: Vec<Validator>,
    quorum: usize,
}

impl ValidatorSet {
    fn new<R: Rng>(size: usize, quorum: usize, rng: &mut R) -> Self {
        let validators = (0..size).map(|_| Validator::new(rng)).collect();
        Self { validators, quorum }
    }

    fn public_keys(&self) -> Vec<PublicKey> {
        self.validators.iter().map(|v| v.public_key()).collect()
    }

    fn raw_public_keys(&self) -> Vec<G1Projective> {
        self.public_keys().iter().map(|pk| pk.0).collect()
    }

    fn rotate<R: Rng>(
        &self,
        kzg_pk: &KzgCommitterKey<ark_bw6_761::G1Affine>,
        rng: &mut R,
    ) -> (ValidatorSet, Vec<Approval>) {
        new_era();
        let new_validator_set = ValidatorSet::new(self.size(), self.quorum, rng);

        let t_approval = start_timer!(|| {
            format!("Each (honest) validators computes the commitment to the new validator set of size {} and signs the commitment", new_validator_set.size())
        });

        let approvals = self
            .validators
            .iter()
            .filter(|_| rng.gen_bool(test_rng().gen_range(6..10) as f64 / 10.0))
            .map(|v| v.approve(&new_validator_set, kzg_pk))
            .collect();

        end_timer!(t_approval);
        println!();

        (new_validator_set, approvals)
    }

    fn size(&self) -> usize {
        self.validators.len()
    }
}

struct LightClient {
    kzg_vk: RawKzgVerifierKey<BW6_761>,
    current_validator_set_commitment: KeysetCommitment,
    quorum: usize,
}

impl LightClient {
    fn init(
        kzg_vk: RawKzgVerifierKey<BW6_761>,
        genesis_keyset_commitment: KeysetCommitment,
        quorum: usize,
    ) -> Self {
        Self {
            kzg_vk,
            current_validator_set_commitment: genesis_keyset_commitment,
            quorum,
        }
    }

    fn verify_aggregates(
        &mut self,
        public_input: AccountablePublicInput,
        proof: &SimpleProof,
        aggregate_signature: &Signature,
        new_validator_set_commitment: KeysetCommitment,
    ) {
        let n_signers = public_input.bitmask.count_ones();
        let t_verification = start_timer!(|| format!(
            "Light client verifies light client proof for {} signers",
            n_signers
        ));

        let t_apk = start_timer!(|| "apk proof verification");
        let verifier = Verifier::new(
            self.kzg_vk.clone(),
            self.current_validator_set_commitment.clone(),
            Transcript::new(b"apk_proof"),
        );
        assert!(verifier.verify_simple(&public_input, &proof));
        end_timer!(t_apk);

        let t_bls = start_timer!(|| "aggregate BLS signature verification");
        let aggregate_public_key = PublicKey(public_input.apk.into_group());
        let message = hash_commitment(&new_validator_set_commitment);
        assert!(aggregate_public_key.verify(&aggregate_signature, &message));
        end_timer!(t_bls);

        assert!(
            n_signers >= self.quorum,
            "{} signers don't make the quorum of {}",
            n_signers,
            self.quorum
        );

        self.current_validator_set_commitment = new_validator_set_commitment;

        end_timer!(t_verification);
    }
}

struct TrustlessHelper {
    kzg_params: URS<BW6_761>,
    current_validator_set: ValidatorSet,
    prover: Prover,
}

impl TrustlessHelper {
    fn new(
        genesis_validator_set: ValidatorSet,
        genesis_validator_set_commitment: &KeysetCommitment,
        kzg_params: URS<BW6_761>,
    ) -> Self {
        let prover = Prover::new(
            Keyset::new(genesis_validator_set.raw_public_keys()),
            genesis_validator_set_commitment,
            kzg_params.clone(),
            Transcript::new(b"apk_proof"),
        );
        Self {
            kzg_params,
            current_validator_set: genesis_validator_set,
            prover,
        }
    }

    fn aggregate_approvals(
        &mut self,
        new_validator_set: ValidatorSet,
        approvals: Vec<Approval>,
    ) -> (
        AccountablePublicInput,
        SimpleProof,
        Signature,
        KeysetCommitment,
    ) {
        let t_approval = start_timer!(|| {
            format!("Helper aggregated {} individual signatures on the same commitment and generates accountable light client proof of them", approvals.len())
        });

        let new_validator_set_commitment = &approvals[0].comm;
        let actual_signers = approvals.iter().map(|a| &a.pk).collect::<HashSet<_>>();
        let actual_signers_bitmask = self
            .current_validator_set
            .public_keys()
            .iter()
            .map(|pk| actual_signers.contains(pk))
            .collect::<Vec<_>>();

        let (proof, public_input) = self
            .prover
            .prove_simple(Bitmask::from_bits(&actual_signers_bitmask));
        let signatures = approvals.iter().map(|a| &a.sig);
        let aggregate_signature = Signature::aggregate(signatures);

        self.current_validator_set = new_validator_set.clone();
        self.prover = Prover::new(
            Keyset::new(new_validator_set.raw_public_keys()),
            new_validator_set_commitment,
            self.kzg_params.clone(),
            Transcript::new(b"apk_proof"),
        );

        end_timer!(t_approval);
        println!();

        (
            public_input,
            proof,
            aggregate_signature,
            new_validator_set_commitment.clone(),
        )
    }
}

fn hash_commitment(commitment: &KeysetCommitment) -> G2Projective {
    let mut buf = vec![0u8; commitment.compressed_size()];
    commitment.serialize_compressed(&mut buf[..]).unwrap();
    hash_to_curve(&buf)
}

fn main() {
    let mut args = std::env::args();
    args.next();

    let log_n: usize = args
        .next()
        .unwrap_or("4".to_string())
        .parse()
        .expect("invalid LOG_N");
    let n_eras: usize = args
        .next()
        .unwrap_or("10".to_string())
        .parse()
        .expect("invalid N_ERAS");

    print!(
        "Running a chain with 2^{}-1 validators for {} eras. ",
        log_n, n_eras
    );
    println!("To change the values run with '--example recursive LOG_N N_ERAS'\n");

    let rng = &mut test_rng(); // Don't use in production code!

    println!("Setup: max validator set size = 2^{}-1\n", log_n);

    let t_setup = start_timer!(|| format!("Generating URS to support 2^{}-1 signers", log_n));
    let kzg_params = setup::generate_for_domain(log_n as u32, rng);
    end_timer!(t_setup);

    let keyset_size = (1 << log_n) - 1;
    let quorum = ((keyset_size * 2) / 3) + 1;

    println!(
        "\nGenesis: validator set size = {}, quorum = {}\n",
        keyset_size, quorum
    );

    let t_genesis = start_timer!(|| format!(
        "Computing commitment to the set of initial {} validators",
        keyset_size
    ));
    let genesis_validator_set = ValidatorSet::new(keyset_size, quorum, rng);
    let keyset = Keyset::new(genesis_validator_set.raw_public_keys());
    let genesis_validator_set_commitment = keyset.commit(&kzg_params.ck());
    end_timer!(t_genesis);

    let mut helper = TrustlessHelper::new(
        genesis_validator_set.clone(),
        &genesis_validator_set_commitment,
        kzg_params.clone(),
    );
    let mut light_client = LightClient::init(
        kzg_params.raw_vk(),
        genesis_validator_set_commitment,
        quorum,
    );

    let mut current_validator_set = genesis_validator_set;

    for era in 1..=n_eras {
        println!("\nEra {}\n", era);
        let (new_validator_set, approvals) = current_validator_set.rotate(&kzg_params.ck(), rng);

        let (public_input, proof, aggregate_signature, new_validator_set_commitment) =
            helper.aggregate_approvals(new_validator_set.clone(), approvals);

        light_client.verify_aggregates(
            public_input,
            &proof,
            &aggregate_signature,
            new_validator_set_commitment,
        );

        current_validator_set = new_validator_set;
    }
}
