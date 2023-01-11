// use halo2::pasta::Fp;

pub mod merkle;
pub mod poseidon;

use halo2_gadgets::poseidon::Pow5Chip;
use halo2_proofs::pasta::Fp;

use crate::{gadget::merkle::*, SemaphoreConfig};

impl<const WIDTH: usize, const RATE: usize> SemaphoreConfig<WIDTH, RATE> {
    pub(super) fn construct_merkle_chip(&self) -> MerkleChip {
        MerkleChip::construct(self.merkle_config.clone())
    }

    // pub(super) fn construct_poseidon_chip(&self) -> PoseidonChip<Fp> {
    //     PoseidonChip::construct(self.poseidon_config.clone())
    // }
    pub(super) fn construct_poseidon_chip(&self) -> Pow5Chip<Fp, WIDTH, RATE> {
        Pow5Chip::construct(self.poseidon_config.clone())
    }
}

