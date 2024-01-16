use num::BigUint;
use plonky2::{
    field::{
        secp256k1_scalar::Secp256K1Scalar,
        types::{Field, Sample},
    },
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};
use plonky2_ecdsa::{
    curve::{
        curve_types::{Curve, CurveScalar},
        ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
        secp256k1::Secp256K1,
    },
    gadgets::{
        curve::CircuitBuilderCurve,
        ecdsa::{verify_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget},
        nonnative::{CircuitBuilderNonNative, NonNativeTarget},
    },
    hash::{
        sha256::{CircuitBuilderHashSha2, WitnessHashSha2},
        CircuitBuilderHash,
    },
};

use sha2::{Digest, Sha256};
fn main() {
    let config = CircuitConfig::standard_ecc_config();
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    type Curve = Secp256K1;

    let mut pw = PartialWitness::new();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let msg = "Hello world!";
    let msg_bytes: &[u8] = msg.as_bytes();
    let blocks_num = msg_bytes.len() / 64 + 1;

    // hash msg natively
    let mut hasher = Sha256::new();
    hasher.update(msg_bytes);
    let hash = hasher.finalize().to_vec();

    // hash msg in circuit
    let hash_input_target = builder.add_virtual_hash_input_target(blocks_num, 512);
    let sha256_output_target = builder.hash_sha256(&hash_input_target);
    pw.set_sha256_input_target(&hash_input_target, &msg_bytes);

    // msg hash as a target in plonky2
    let msg_hash_field_target: NonNativeTarget<Secp256K1Scalar> =
        builder.reduce(&sha256_output_target);

    // msg hash in native field outside circuit
    let hash_bigint = convert_hash_to_biguint(&hash);
    let msg_hash_field = Secp256K1Scalar::from_noncanonical_biguint(hash_bigint);

    // randomly generate a secret key and derive public key
    let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
    let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

    // public key as target in circuit
    let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk.0));

    // ecdsa sign outside the circuit
    let sig = sign_message(msg_hash_field, sk);

    // set up targets related to signature in circuit
    let ECDSASignature { r, s } = sig;
    let r_target = builder.constant_nonnative(r);
    let s_target = builder.constant_nonnative(s);
    let sig_target = ECDSASignatureTarget {
        r: r_target,
        s: s_target,
    };

    // signature verification circuit
    verify_message_circuit(&mut builder, msg_hash_field_target, sig_target, pk_target);

    dbg!(builder.num_gates());
    let data = builder.build::<C>();
    let proof = data.prove(pw).unwrap();
    println!("proof size: {}", proof.public_inputs.len());
    assert!(data.verify(proof).is_ok());
}

// This is required since hash target as BigUint seems to be
// arranged differently that usual BigUint as Vec of u32
fn convert_hash_to_biguint(array: &[u8]) -> BigUint {
    let bigint = BigUint::from_bytes_le(array);
    let mut u32s = bigint.to_u32_digits();
    u32s.iter_mut().for_each(|x| *x = x.to_be());
    BigUint::from_slice(&u32s)
}
