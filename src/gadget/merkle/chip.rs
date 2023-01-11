// use halo2::{
//     circuit::{Chip, Layouter},
//     pasta::Fp,
//     plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
//     poly::Rotation,
// };

use halo2_gadgets::poseidon::Pow5Config;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, Value};
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;

// use super::super::super::CellValue;
use super::MerkleInstructions;
// use crate::utils::Var;

// use crate::primitives::poseidon::{ConstantLength, P128Pow5T3};

#[derive(Clone, Debug)]
pub struct MerkleConfig {
    pub advice: [Column<Advice>; 3],
    pub s_bool: Selector,
    pub s_swap: Selector,
    pub hash_config: Pow5Config<Fp>,
}

#[derive(Clone, Debug)]
pub struct MerkleChip {
    pub config: MerkleConfig,
}

impl Chip<Fp> for MerkleChip {
    type Config = MerkleConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl MerkleChip {
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; 3],
        hash_config: PoseidonConfig<Fp>,
    ) -> <Self as Chip<Fp>>::Config {
        for column in &advice {
            meta.enable_equality((*column).into());
        }

        let s_bool = meta.selector();

        meta.create_gate("bool", |meta| {
            let position_bit = meta.query_advice(advice[2], Rotation::cur());
            let s_bool = meta.query_selector(s_bool);
            vec![s_bool * position_bit.clone() * (Expression::Constant(Fp::one()) - position_bit)]
        });

        let s_swap = meta.selector();

        meta.create_gate("swap", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let bit = meta.query_advice(advice[2], Rotation::cur());
            let s_swap = meta.query_selector(s_swap);
            let l = meta.query_advice(advice[0], Rotation::next());
            let r = meta.query_advice(advice[1], Rotation::next());
            vec![s_swap * ((bit * Fp::from(2) * (b.clone() - a.clone()) - (l - a)) - (b - r))]
        });

        let hash_config = hash_config.clone();

        MerkleConfig {
            advice,
            s_bool,
            s_swap,
            hash_config,
        }
    }

    pub fn construct(config: <Self as Chip<Fp>>::Config) -> Self {
        Self { config }
    }
}
// ANCHOR_END: chip-config

impl MerkleInstructions for MerkleChip {
    // type Cell = CellValue<Fp>;
    type Cell = AssignedCell<Fp, Fp>;

    fn hash_layer(
        &self,
        mut layouter: impl Layouter<Fp>,
        leaf_or_digest: Self::Cell,
        // sibling: Option<Fp>,
        // position_bit: Option<Fp>,
        sibling: Value<Fp>,
        position_bit: Value<Fp>,
        layer: usize,
    ) -> Result<Self::Cell, Error> {
        let config = self.config.clone();

        let mut left_digest = None;
        let mut right_digest = None;

        layouter.assign_region(
            || format!("hash on (layer {})", layer),
            |mut region| {
                let mut row_offset = 0;

                let left_or_digest_value = leaf_or_digest;

                let left_or_digest_cell = region.assign_advice(
                    || format!("witness leaf or digest (layer {})", layer),
                    config.advice[0],
                    row_offset,
                    || left_or_digest_value.value().copied(),
                )?;

                if layer > 0 {
                    region.constrain_equal(leaf_or_digest.cell(), left_or_digest_cell.cell())?;
                    // Should i do permutation here?
                }

                let _sibling_cell = region.assign_advice(
                    || format!("witness sibling (layer {})", layer),
                    config.advice[1],
                    row_offset,
                    || sibling,
                )?;

                let _position_bit_cell = region.assign_advice(
                    || format!("witness positional_bit (layer {})", layer),
                    config.advice[2],
                    row_offset,
                    || position_bit,
                )?;

                config.s_bool.enable(&mut region, row_offset)?;
                config.s_swap.enable(&mut region, row_offset)?;

                // let (l_value, r_value): (Fp, Fp) = if position_bit == Some(Fp::zero()) {
                //     (
                //         left_or_digest_value.ok_or(Error::Synthesis)?,
                //         sibling.ok_or(Error::Synthesis)?,
                //     )
                // } else {
                //     (
                //         sibling.ok_or(Error::Synthesis)?,
                //         left_or_digest_value.ok_or(Error::Synthesis)?,
                //     )
                // };
                //

                row_offset += 1;

                let l_value = {
                    left_or_digest_value
                        .value()
                        .copied()
                        .zip(sibling)
                        .zip(position_bit)
                        .map(|((a, b), swap)| if swap == Fp::zero() { a } else { b })
                };

                region.assign_advice(|| "a_swapped", config.advice[0], 0, || l_value)?;

                // let l_cell = region.assign_advice(
                //     || format!("witness left (layer {})", layer),
                //     config.advice[0],
                //     row_offset,
                //     || Ok(l_value),
                // )?;
                //
                let r_value = {
                    left_or_digest_value
                        .value()
                        .copied()
                        .zip(sibling)
                        .zip(position_bit)
                        .map(|((a, b), swap)| if swap == Fp::zero() { b } else { a })
                };

                let r_cell = region.assign_advice(
                    || format!("witness right (layer {})", layer),
                    config.advice[1],
                    row_offset,
                    || r_value,
                )?;

                Ok(())
            },
        )?;

        let poseidon_chip = PoseidonChip::construct(config.hash_config.clone());
        let mut poseidon_hasher: PoseidonHash<
            Fp,
            PoseidonChip<Fp>,
            P128Pow5T3,
            ConstantLength<2_usize>,
            3_usize,
            2_usize,
        > = PoseidonHash::init(
            poseidon_chip,
            layouter.namespace(|| "init hasher"),
            ConstantLength::<2>,
        )?;

        let message = [left_digest.unwrap(), right_digest.unwrap()];

        let loaded_message = poseidon_hasher.witness_message_pieces(
            config.hash_config.clone(),
            layouter.namespace(|| format!("witnessing hash of a layer: {}", layer)),
            message,
        )?;

        let word = poseidon_hasher.hash(
            layouter.namespace(|| format!("hashing layer: {}", layer)),
            loaded_message,
        )?;
        let digest: CellValue<Fp> = word.inner().into();

        Ok(digest)
    }
}
