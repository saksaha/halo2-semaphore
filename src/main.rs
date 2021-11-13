use halo2::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Advice, Instance, Circuit, Column, ConstraintSystem, Error},
    pasta::Fp
};
use std::marker::PhantomData;

mod gadget;
mod utils;

use gadget:: {
    add::{AddChip, AddConfig, AddInstruction},
    merkle::{MerkleChip, MerkleConfig, MerklePath}
};

use crate:: {
    utils::{UtilitiesInstructions, CellValue}
};

pub const MERKLE_DEPTH: usize = 4;

// Absolute offsets for public inputs.
const EXTERNAL_NULLIFIER: usize = 0;
const NULLIFIER_HASH: usize = 1;
const ROOT: usize = 2;

// Semaphore config
#[derive(Clone, Debug)]
pub struct Config<F> {
    advices: [Column<Advice>; 4],
    instance: Column<Instance>,
    add_config: AddConfig,
    merkle_config: MerkleConfig,
    pub _marker: PhantomData<F>,
}

// Semaphore circuit
#[derive(Debug, Default)]
pub struct SemaphoreCircuit<F> {
    identity_trapdoor: Option<F>,
    identity_nullifier: Option<F>,
    external_nullifier: Option<F>,
    position_bits: Option<[F; MERKLE_DEPTH]>,
    path: Option<[F; MERKLE_DEPTH]>,
    root: Option<F>,
}

impl<F: FieldExt> UtilitiesInstructions<F> for SemaphoreCircuit<F> {
    type Var = CellValue<F>;
}

impl<F: FieldExt> Circuit<F> for SemaphoreCircuit<F> {
    type Config = Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {

        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        let instance = meta.instance_column();
        meta.enable_equality(instance.into());

        for advice in advices.iter() {
            meta.enable_equality((*advice).into());
        }

        let add_config = AddChip::configure(meta, advices[0..2].try_into().unwrap());
        let merkle_config = MerkleChip::configure(meta, advices[0..3].try_into().unwrap());

        Config {
            advices, 
            instance,
            add_config,
            merkle_config,
            _marker: PhantomData
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {

        let add_chip = config.construct_add_chip();
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
            self.external_nullifier
        )?;

        self.load_private(
            layouter.namespace(|| "witness root"),
            config.advices[0],
            self.root,
        )?;

        let identity_commitment = add_chip.add(layouter.namespace(|| "commitment"), identity_nullifier, identity_trapdoor)?;
        let nullifier_hash = add_chip.add(layouter.namespace(|| "nullifier"), identity_nullifier, external_nulifier)?;

        let merkle_inputs = MerklePath {
            chip: merkle_chip,
            leaf_pos: self.position_bits,
            path: self.path
        };

        let calculated_root = merkle_inputs.calculate_root(
            layouter.namespace(|| "merkle root calculation"),
            identity_commitment
        )?;

        
        self.expose_public(layouter.namespace(|| "constrain external_nullifier"), config.instance, external_nulifier, EXTERNAL_NULLIFIER)?;
        self.expose_public(layouter.namespace(|| "constrain nullifier_hash"), config.instance, nullifier_hash, NULLIFIER_HASH)?;
        self.expose_public(layouter.namespace(|| "constrain root"), config.instance, calculated_root, ROOT)?;

        Ok({})
    }
}


fn main() {
    use halo2::{dev::MockProver};

    let k = 5;

    let identity_trapdoor = Fp::from(2);
    let identity_nullifier = Fp::from(3);
    let external_nullifier = Fp::from(5);
    let path = [Fp::from(1), Fp::from(1), Fp::from(1), Fp::from(1)];
    let position_bits = [Fp::from(0), Fp::from(1), Fp::from(0), Fp::from(1)];
    let identity_commitment = identity_trapdoor + identity_nullifier;
    let nullifier_hash = identity_nullifier + external_nullifier;

    let root = identity_commitment + Fp::from(4);

    let circuit = SemaphoreCircuit {
        identity_trapdoor: Some(identity_trapdoor),
        identity_nullifier: Some(identity_nullifier),
        external_nullifier: Some(external_nullifier),
        position_bits: Some(position_bits),
        path: Some(path),
        root: Some(root)
    };

    let mut public_inputs = vec![external_nullifier, nullifier_hash, root];

    // Given the correct public input, our circuit will verify.
    let prover = MockProver::run(k, &circuit, vec![public_inputs.clone()]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    // If we try some other public input, the proof will fail!
    public_inputs[0] += Fp::one();
    let prover = MockProver::run(k, &circuit, vec![public_inputs]).unwrap();
    assert!(prover.verify().is_err());
}
