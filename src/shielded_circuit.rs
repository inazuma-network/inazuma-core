//! Groth16 spend circuit for the shielded pool (2-in / 2-out joinsplit).
//!
//! A proof demonstrates, without revealing anything else:
//!   1. each spent note's commitment sits in the tree at the public anchor
//!      root (Merkle membership, TREE_DEPTH Poseidon compressions)
//!   2. the prover knows the spend key behind each note's owner tag
//!   3. each public nullifier is correctly derived from (spend key, position)
//!   4. value is conserved: sum(inputs) = sum(outputs) + public_unshield
//!   5. every value fits 64 bits (no wrap-around minting via field overflow)
//!
//! Public inputs (order is consensus-critical):
//!   [anchor, nf1, nf2, cm_new1, cm_new2, public_unshield]
//!
//! The circuit is deliberately symmetric: unused slots carry zero-value notes
//! with a zero spend key, so `unshield` (1-in/1-out) and change-style spends
//! use the same circuit and params as full 2-in/2-out transfers.

use crate::poseidon::{self, POSEIDON_RF, POSEIDON_RP, POSEIDON_T};
use crate::shielded::{self, TREE_DEPTH};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{rngs::StdRng, SeedableRng};

/// In-circuit Poseidon, identical round schedule to `poseidon::permute`.
fn poseidon_hash2_gadget(
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let p = poseidon::params();
    let mut state: Vec<FpVar<Fr>> = vec![a.clone(), b.clone(), FpVar::constant(Fr::from(0u64))];
    let full_half = POSEIDON_RF / 2;
    for round in 0..(POSEIDON_RF + POSEIDON_RP) {
        for (j, s) in state.iter_mut().enumerate() {
            *s += Fr::from(poseidon::params().ark[round * POSEIDON_T + j]);
        }
        let partial = round >= full_half && round < full_half + POSEIDON_RP;
        if partial {
            state[0] = state[0].pow_by_constant([5u64])?;
        } else {
            for s in state.iter_mut() {
                *s = s.pow_by_constant([5u64])?;
            }
        }
        let old = state.clone();
        for (j, s) in state.iter_mut().enumerate() {
            let mut acc = FpVar::constant(Fr::from(0u64));
            for (k, o) in old.iter().enumerate() {
                acc += o * Fr::from(p.mds[j][k]);
            }
            *s = acc;
        }
    }
    Ok(state[0].clone())
}

fn commit_gadget(
    owner: &FpVar<Fr>,
    value: &FpVar<Fr>,
    rho: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon_hash2_gadget(&poseidon_hash2_gadget(owner, value)?, rho)
}

/// Range-check: value < 2^64, enforced by decomposing to bits and requiring
/// every bit at position >= 64 to be zero.
fn range_check_64(v: &FpVar<Fr>) -> Result<(), SynthesisError> {
    let bits = v.to_bits_le()?;
    for b in bits.iter().skip(64) {
        b.enforce_equal(&Boolean::FALSE)?;
    }
    Ok(())
}

/// One witness note being spent.
#[derive(Clone)]
pub struct SpendNote {
    pub spend_key: Fr,
    pub value: u128,
    pub rho: Fr,
    pub position: u64,
    /// TREE_DEPTH sibling hashes, bottom level first.
    pub path: Vec<Fr>,
}

/// One output note being created (contents are private witnesses; only the
/// commitment is public).
#[derive(Clone)]
pub struct OutputNote {
    pub owner: Fr,
    pub value: u128,
    pub rho: Fr,
}

#[derive(Clone)]
pub struct SpendCircuit {
    // public
    pub anchor: Fr,
    pub nullifiers: [Fr; 2],
    pub out_commitments: [Fr; 2],
    pub public_unshield: u128,
    // private
    pub inputs: [SpendNote; 2],
    pub outputs: [OutputNote; 2],
}

impl ConstraintSynthesizer<Fr> for SpendCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let anchor = FpVar::new_input(cs.clone(), || Ok(self.anchor))?;
        let nf_pub: Vec<_> = self
            .nullifiers
            .iter()
            .map(|n| FpVar::new_input(cs.clone(), || Ok(*n)))
            .collect::<Result<_, _>>()?;
        let cm_pub: Vec<_> = self
            .out_commitments
            .iter()
            .map(|c| FpVar::new_input(cs.clone(), || Ok(*c)))
            .collect::<Result<_, _>>()?;
        let pub_unshield = FpVar::new_input(cs.clone(), || Ok(poseidon::fr_u128(self.public_unshield)))?;
        range_check_64(&pub_unshield)?;

        let mut in_sum = FpVar::constant(Fr::from(0u64));
        for (i, note) in self.inputs.iter().enumerate() {
            let sk = FpVar::new_witness(cs.clone(), || Ok(note.spend_key))?;
            let value = FpVar::new_witness(cs.clone(), || Ok(poseidon::fr_u128(note.value)))?;
            let rho = FpVar::new_witness(cs.clone(), || Ok(note.rho))?;
            let position = FpVar::new_witness(cs.clone(), || Ok(Fr::from(note.position)))?;
            range_check_64(&value)?;

            // Ownership: owner tag = H(sk, 0), commitment binds it.
            let owner = poseidon_hash2_gadget(&sk, &FpVar::constant(Fr::from(0u64)))?;
            let cm = commit_gadget(&owner, &value, &rho)?;

            // Merkle membership. Direction bits come from the position
            // witness; they are constrained to be bits and to sum back to
            // `position`, so the path can never be mis-declared.
            let pos_bits = position.to_bits_le()?;
            for b in pos_bits.iter().skip(TREE_DEPTH) {
                b.enforce_equal(&Boolean::FALSE)?;
            }
            let mut cur = cm;
            for (level, sibling_fr) in note.path.iter().enumerate() {
                let sibling = FpVar::new_witness(cs.clone(), || Ok(sibling_fr))?;
                let bit = &pos_bits[level];
                let left = FpVar::conditionally_select(bit, &sibling, &cur)?;
                let right = FpVar::conditionally_select(bit, &cur, &sibling)?;
                cur = poseidon_hash2_gadget(&left, &right)?;
            }
            // Zero-value notes are dummies (the unused slot in a 1-in spend):
            // their commitment is not in the tree, so membership is only
            // enforced for notes carrying value. A dummy's spend key is a
            // free witness — use a random one so its nullifier is unique.
            let is_dummy = value.is_zero()?;
            let enforce = FpVar::conditionally_select(
                &is_dummy.not(),
                &FpVar::constant(Fr::from(1u64)),
                &FpVar::constant(Fr::from(0u64)),
            )?;
            ((cur - &anchor) * enforce).enforce_equal(&FpVar::constant(Fr::from(0u64)))?;

            // Nullifier = H(sk, position), must equal the public one.
            let nf = poseidon_hash2_gadget(&sk, &position)?;
            nf.enforce_equal(&nf_pub[i])?;

            in_sum += value;
        }

        let mut out_sum = pub_unshield;
        for (i, out) in self.outputs.iter().enumerate() {
            let owner = FpVar::new_witness(cs.clone(), || Ok(out.owner))?;
            let value = FpVar::new_witness(cs.clone(), || Ok(poseidon::fr_u128(out.value)))?;
            let rho = FpVar::new_witness(cs.clone(), || Ok(out.rho))?;
            range_check_64(&value)?;
            let cm = commit_gadget(&owner, &value, &rho)?;
            cm.enforce_equal(&cm_pub[i])?;
            out_sum += value;
        }

        in_sum.enforce_equal(&out_sum)?;
        Ok(())
    }
}

// ---- proving / verifying glue ----

/// Deterministic devnet setup. A production ceremony replaces these params;
/// the seed is public, so proofs from these params are NOT production-safe —
/// they are for devnet and testing only, and `docs/shielded.md` says so.
pub fn devnet_setup() -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
    let mut rng = StdRng::seed_from_u64(0x1A42_5113_D3D0_0001);
    let dummy = SpendCircuit {
        anchor: shielded::zero_subtree_root(TREE_DEPTH),
        nullifiers: [Fr::from(0u64), Fr::from(0u64)],
        out_commitments: [Fr::from(0u64), Fr::from(0u64)],
        public_unshield: 0,
        inputs: [
            SpendNote {
                spend_key: Fr::from(0u64),
                value: 0,
                rho: Fr::from(0u64),
                position: 0,
                path: (0..TREE_DEPTH).map(shielded::zero_subtree_root).collect(),
            },
            SpendNote {
                spend_key: Fr::from(0u64),
                value: 0,
                rho: Fr::from(0u64),
                position: 0,
                path: (0..TREE_DEPTH).map(shielded::zero_subtree_root).collect(),
            },
        ],
        outputs: [
            OutputNote { owner: Fr::from(0u64), value: 0, rho: Fr::from(0u64) },
            OutputNote { owner: Fr::from(0u64), value: 0, rho: Fr::from(0u64) },
        ],
    };
    Groth16::<Bn254>::generate_random_parameters_with_reduction(dummy, &mut rng).map(|pk| {
        let vk = pk.vk.clone();
        (pk, vk)
    })
    .expect("setup")
}

pub fn prove(pk: &ProvingKey<Bn254>, circuit: SpendCircuit) -> Result<Proof<Bn254>, String> {
    let mut rng = StdRng::seed_from_u64(rand_seed());
    Groth16::<Bn254>::create_random_proof_with_reduction(circuit, pk, &mut rng)
        .map_err(|e| format!("prove: {e}"))
}

fn rand_seed() -> u64 {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).unwrap_or_default();
    u64::from_le_bytes(b)
}

pub fn public_inputs(c: &SpendCircuit) -> Vec<Fr> {
    vec![
        c.anchor,
        c.nullifiers[0],
        c.nullifiers[1],
        c.out_commitments[0],
        c.out_commitments[1],
        poseidon::fr_u128(c.public_unshield),
    ]
}

pub fn verify(vk: &VerifyingKey<Bn254>, proof: &Proof<Bn254>, inputs: &[Fr]) -> bool {
    let pvk = ark_groth16::prepare_verifying_key(vk);
    Groth16::<Bn254>::verify_proof(&pvk, proof, inputs).unwrap_or(false)
}

pub fn proof_to_hex(p: &Proof<Bn254>) -> String {
    let mut b = Vec::new();
    p.serialize_compressed(&mut b).expect("serialize");
    hex::encode(b)
}

pub fn proof_from_hex(s: &str) -> Option<Proof<Bn254>> {
    let raw = hex::decode(s.trim()).ok()?;
    Proof::<Bn254>::deserialize_compressed(&raw[..]).ok()
}

pub fn vk_to_hex(vk: &VerifyingKey<Bn254>) -> String {
    let mut b = Vec::new();
    vk.serialize_compressed(&mut b).expect("serialize");
    hex::encode(b)
}

pub fn vk_from_hex(s: &str) -> Option<VerifyingKey<Bn254>> {
    let raw = hex::decode(s.trim()).ok()?;
    VerifyingKey::<Bn254>::deserialize_compressed(&raw[..]).ok()
}

pub fn vk_to_bytes(vk: &VerifyingKey<Bn254>) -> Vec<u8> {
    let mut b = Vec::new();
    vk.serialize_compressed(&mut b).expect("serialize");
    b
}

pub fn pk_to_bytes(pk: &ProvingKey<Bn254>) -> Vec<u8> {
    let mut b = Vec::new();
    pk.serialize_compressed(&mut b).expect("serialize");
    b
}

pub fn pk_from_bytes(b: &[u8]) -> Option<ProvingKey<Bn254>> {
    ProvingKey::<Bn254>::deserialize_compressed(b).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny in-memory tree with two notes and return everything a
    /// valid 2-in/2-out spend needs.
    fn fixture() -> (SpendCircuit, Fr, [Fr; 2], [Fr; 2]) {
        let sk1 = Fr::from(111u64);
        let sk2 = Fr::from(222u64);
        let owner1 = shielded::owner_tag(sk1);
        let owner2 = shielded::owner_tag(sk2);
        let cm1 = shielded::note_commitment(owner1, 50, Fr::from(1u64));
        let cm2 = shielded::note_commitment(owner2, 70, Fr::from(2u64));

        // Depth-32 tree with leaves [cm1, cm2]: compute paths natively.
        let leaves = [cm1, cm2];
        let path1 = shielded::merkle_path(&leaves, 0).unwrap();
        let path2 = shielded::merkle_path(&leaves, 1).unwrap();
        let root = shielded::root_from_leaves(&leaves);

        let out1 = OutputNote { owner: Fr::from(9u64), value: 90, rho: Fr::from(3u64) };
        let out2 = OutputNote { owner: Fr::from(8u64), value: 30, rho: Fr::from(4u64) };
        let cm3 = shielded::note_commitment(out1.owner, out1.value, out1.rho);
        let cm4 = shielded::note_commitment(out2.owner, out2.value, out2.rho);

        let circuit = SpendCircuit {
            anchor: root,
            nullifiers: [shielded::nullifier(sk1, 0), shielded::nullifier(sk2, 1)],
            out_commitments: [cm3, cm4],
            public_unshield: 0,
            inputs: [
                SpendNote { spend_key: sk1, value: 50, rho: Fr::from(1u64), position: 0, path: path1 },
                SpendNote { spend_key: sk2, value: 70, rho: Fr::from(2u64), position: 1, path: path2 },
            ],
            outputs: [out1, out2],
        };
        (circuit, root, [cm3, cm4], [shielded::nullifier(sk1, 0), shielded::nullifier(sk2, 1)])
    }

    #[test]
    fn valid_spend_proves_and_verifies() {
        let (pk, vk) = devnet_setup();
        let (circuit, ..) = fixture();
        let inputs = public_inputs(&circuit);
        let proof = prove(&pk, circuit).expect("prove");
        assert!(verify(&vk, &proof, &inputs));
    }

    #[test]
    fn forged_value_is_rejected() {
        let (pk, vk) = devnet_setup();
        let (mut circuit, ..) = fixture();
        // Try to create money out of thin air: outputs exceed inputs.
        circuit.outputs[0].value = 999;
        circuit.out_commitments[0] = shielded::note_commitment(
            circuit.outputs[0].owner,
            999,
            circuit.outputs[0].rho,
        );
        let inputs = public_inputs(&circuit);
        match prove(&pk, circuit) {
            Ok(proof) => assert!(!verify(&vk, &proof, &inputs), "forgery verified!"),
            Err(_) => {} // unsatisfied constraints — also correct
        }
    }

    #[test]
    fn wrong_spend_key_is_rejected() {
        let (pk, vk) = devnet_setup();
        let (mut circuit, ..) = fixture();
        circuit.inputs[0].spend_key = Fr::from(999u64); // attacker key
        let inputs = public_inputs(&circuit);
        match prove(&pk, circuit) {
            Ok(proof) => assert!(!verify(&vk, &proof, &inputs)),
            Err(_) => {}
        }
    }
}
