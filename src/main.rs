// use halo2::{
//     circuit::{Layouter, SimpleFloorPlanner},
//     pasta::Fp,
//     plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
// };

use std::marker::PhantomData;

use halo2_gadgets::{
    poseidon::{
        primitives::{ConstantLength, Spec},
        Hash, Pow5Chip, Pow5Config, Word,
    },
    utilities::{UtilitiesInstructions, Var},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    pasta::{pallas, Fp},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
    // poly::Error,
};
// use pasta_curves::pallas;

mod gadget;
mod primitives;
mod utils;

use gadget::merkle::{MerkleChip, MerkleConfig, MerklePath};

// use crate::primitives::poseidon::{ConstantLength, P128Pow5T3};

pub const MERKLE_DEPTH: usize = 4;

// Absolute offsets for public inputs.
const EXTERNAL_NULLIFIER: usize = 0;
const NULLIFIER_HASH: usize = 1;
const ROOT: usize = 2;

// Semaphore config
#[derive(Clone, Debug)]
pub struct SemaphoreConfig<const WIDTH: usize, const RATE: usize> {
    advices: Vec<Column<Advice>>,
    instance: Column<Instance>,
    merkle_config: MerkleConfig,
    poseidon_config: Pow5Config<Fp, WIDTH, RATE>,
}

// Semaphore circuit
#[derive(Debug, Default)]
pub struct SemaphoreCircuit<S, const WIDTH: usize, const RATE: usize>
where
    S: Spec<Fp, WIDTH, RATE>,
{
    identity_trapdoor: Value<Fp>,
    identity_nullifier: Value<Fp>,
    external_nullifier: Value<Fp>,
    position_bits: Value<[Fp; MERKLE_DEPTH]>,
    path: Value<[Fp; MERKLE_DEPTH]>,
    _spec: PhantomData<S>,
}

// impl UtilitiesInstructions<pallas::Base> for SemaphoreCircuit {
//     type Var = CellValue<pallas::Base>;
// }
//
impl<S, const WIDTH: usize, const RATE: usize> UtilitiesInstructions<Fp>
    for SemaphoreCircuit<S, WIDTH, RATE>
where
    S: Spec<Fp, WIDTH, RATE>,
{
    type Var = AssignedCell<Fp, Fp>;
}

impl<S, const WIDTH: usize, const RATE: usize> SemaphoreCircuit<S, WIDTH, RATE>
where
    S: Spec<Fp, WIDTH, RATE>,
{
    fn hash(
        &self,
        config: SemaphoreConfig<WIDTH, RATE>,
        mut layouter: impl Layouter<Fp>,
        // message: [CellValue<Fp>; 2],
        message: [AssignedCell<Fp, Fp>; 2],
        to_hash: &str,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let config = config.clone();

        let poseidon_chip = config.construct_poseidon_chip();

        let mut poseidon_hasher: Hash<
            Fp,
            Pow5Chip<Fp, WIDTH, RATE>,
            S,
            ConstantLength<2_usize>,
            WIDTH,
            RATE,
        > = Hash::init(
            poseidon_chip,
            layouter.namespace(|| "init hasher"),
            // ConstantLength::<2>,
        )?;

        // let loaded_message = poseidon_hasher.witness_message_pieces(
        //     config.poseidon_config,
        //     layouter.namespace(|| format!("witnessing: {}", to_hash)),
        //     message,
        // )?;

        let digest = poseidon_hasher.hash(
            layouter.namespace(|| format!("hashing: {}", to_hash)),
            message,
        )?;

        // let digest: AssignedCell<Fp, Fp> = word.inner().into();

        Ok(digest)
    }
}

impl<S, const WIDTH: usize, const RATE: usize> Circuit<pallas::Base>
    for SemaphoreCircuit<S, WIDTH, RATE>
where
    S: Spec<Fp, WIDTH, RATE>,
{
    type Config = SemaphoreConfig<WIDTH, RATE>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            identity_trapdoor: Value::unknown(),
            identity_nullifier: Value::unknown(),
            external_nullifier: Value::unknown(),
            position_bits: Value::unknown(),
            path: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();

        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        meta.enable_constant(rc_b[0]);

        // let poseidon_config = PoseidonChip::configure(
        //     meta,
        //     P128Pow5T3,
        //     advices[0..3].try_into().unwrap(),
        //     advices[3],
        //     rc_a,
        //     rc_b,
        // );

        let poseidon_config = Pow5Chip::configure::<S>(
            meta,
            state.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        let merkle_config =
            MerkleChip::configure(meta, state.try_into().unwrap(), poseidon_config.clone());

        let instance = meta.instance_column();
        meta.enable_equality(instance.into());

        SemaphoreConfig {
            // advices,
            advices: state,
            instance,
            merkle_config,
            poseidon_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let merkle_chip = config.construct_merkle_chip();

        let identity_trapdoor = self.load_private(
            layouter.namespace(|| "witness identity_trapdoor"),
            config.advices[0],
            self.identity_trapdoor,
        )?;

        let identity_nullifier = self.load_private(
            layouter.namespace(|| "witness identity_nullifier"),
            config.advices[0],
            self.identity_nullifier,
        )?;

        let external_nulifier = self.load_private(
            layouter.namespace(|| "witness external nullifier"),
            config.advices[0],
            self.external_nullifier,
        )?;

        let identity_commitment_message = [identity_trapdoor, identity_nullifier];
        let identity_commitment = self.hash(
            config.clone(),
            layouter.namespace(|| "hash to identity commitment"),
            identity_commitment_message,
            "identity commitment",
        )?;

        // println!("Identity Commitment: {:?}", identity_commitment.value());

        let nullifier_hash_message = [identity_nullifier, external_nulifier];
        let nullifier_hash = self.hash(
            config.clone(),
            layouter.namespace(|| "hash to nullifier hash"),
            nullifier_hash_message,
            "nullifier hash",
        )?;

        // println!("Nullifier hash: {:?}", nullifier_hash.value());

        let merkle_inputs = MerklePath {
            chip: merkle_chip,
            leaf_pos: self.position_bits,
            path: self.path,
        };

        let calculated_root = merkle_inputs.calculate_root(
            layouter.namespace(|| "merkle root calculation"),
            identity_commitment,
        )?;

        self.expose_public(
            layouter.namespace(|| "constrain external_nullifier"),
            config.instance,
            external_nulifier,
            EXTERNAL_NULLIFIER,
        )?;
        self.expose_public(
            layouter.namespace(|| "constrain nullifier_hash"),
            config.instance,
            nullifier_hash,
            NULLIFIER_HASH,
        )?;
        self.expose_public(
            layouter.namespace(|| "constrain root"),
            config.instance,
            calculated_root,
            ROOT,
        )?;

        Ok({})
    }
}

fn main() {
    // use halo2::dev::MockProver;

    use crate::primitives::poseidon::Hash;

    println!("111111111");

    let k = 10;

    let identity_trapdoor = Fp::from(2);
    let identity_nullifier = Fp::from(3);
    let external_nullifier = Fp::from(5);
    let path = [Fp::from(1), Fp::from(1), Fp::from(1), Fp::from(1)];
    let position_bits = [Fp::from(1), Fp::from(0), Fp::from(0), Fp::from(0)];

    let message = [identity_nullifier, external_nullifier];
    let nullifier_hash = Hash::init(P128Pow5T3, ConstantLength::<2>).hash(message);

    let commitment_message = [identity_trapdoor, identity_nullifier];
    let identity_commitment = Hash::init(P128Pow5T3, ConstantLength::<2>).hash(commitment_message);

    let mut root = identity_commitment;

    // for el in path {
    //     root = Hash::init(P128Pow5T3, ConstantLength::<2>).hash([root, el]);
    // }
    //
    root = Hash::init(P128Pow5T3, ConstantLength::<2>).hash([path[0], root]);
    root = Hash::init(P128Pow5T3, ConstantLength::<2>).hash([root, path[1]]);
    root = Hash::init(P128Pow5T3, ConstantLength::<2>).hash([root, path[2]]);
    root = Hash::init(P128Pow5T3, ConstantLength::<2>).hash([root, path[3]]);

    println!("root: {:?}", root);

    let circuit = SemaphoreCircuit {
        identity_trapdoor: Some(identity_trapdoor),
        identity_nullifier: Some(identity_nullifier),
        external_nullifier: Some(external_nullifier),
        position_bits: Some(position_bits),
        path: Some(path),
    };

    let mut public_inputs = vec![external_nullifier, nullifier_hash, root];

    // Given the correct public input, our circuit will verify.
    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
    println!("22 proven!");

    // // If we try some other public input, the proof will fail!
    // public_inputs[0] += Fp::one();
    // let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    // assert!(prover.verify().is_err());
}
