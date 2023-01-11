// use halo2::{
//     circuit::{Chip, Layouter},
//     pasta::Fp,
//     plonk::Error,
// };

mod chip;
use super::super::MERKLE_DEPTH;
pub use chip::{MerkleChip, MerkleConfig};
use halo2_proofs::{
    circuit::{Chip, Layouter, Value},
    pasta::Fp,
    plonk::Error,
};

pub trait MerkleInstructions: Chip<Fp> {
    type Cell;

    fn hash_layer(
        &self,
        layouter: impl Layouter<Fp>,
        leaf_or_digest: Self::Cell,
        sibling: Value<Fp>,
        position_bit: Value<Fp>,
        layer: usize,
    ) -> Result<Self::Cell, Error>;
}

#[derive(Clone, Debug)]
pub struct MerklePath<MerkleChip>
where
    MerkleChip: MerkleInstructions + Clone,
{
    pub chip: MerkleChip,
    pub leaf_pos: Value<[Fp; MERKLE_DEPTH]>,

    // The Merkle path is ordered from leaves to root.
    pub path: Value<[Fp; MERKLE_DEPTH]>,
}

impl MerklePath<MerkleChip>
where
    MerkleChip: MerkleInstructions + Clone,
{
    pub fn calculate_root(
        &self,
        mut layouter: impl Layouter<Fp>,
        leaf: <MerkleChip as MerkleInstructions>::Cell,
    ) -> Result<<MerkleChip as MerkleInstructions>::Cell, Error> {
        let mut node = leaf;

        let path = self.path;
        let leaf_pos = self.leaf_pos;

        for layer in 0..MERKLE_DEPTH {
            let sibling = self.path.map(|path| path[layer]);
            let pos = self.leaf_pos.map(|leaf| leaf[layer]);

            println!("layer: {:?}, pos: {:?}, sibling: {:?}", layer, pos, sibling);

            node = self.chip.hash_layer(
                layouter.namespace(|| format!("hash l {}", layer)),
                node,
                sibling,
                pos,
                layer,
            )?;
        }

        // for (layer, (sibling, pos)) in path.iter().zip(leaf_pos.iter()).enumerate() {
        //     println!("layer: {:?}, pos: {:?}, sibling: {:?}", layer, pos, sibling);

        //     node = self.chip.hash_layer(
        //         layouter.namespace(|| format!("hash l {}", layer)),
        //         node,
        //         Some(*sibling),
        //         Some(*pos),
        //         layer,
        //     )?;
        // }

        Ok(node)
    }
}
