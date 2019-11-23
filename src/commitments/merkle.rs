use std::cmp::max;
use bitcoin_hashes::sha256;

pub struct Digest<T>(pub sha256::Hash);

pub trait Digestible {
    fn get_digest(&self) -> Digest<Self>;
}


pub enum MerkleBranch<T: Digestible> {
    Branch(Digest<MerkeNode<T>>),
    Leaf(Digest<T>)
}

impl<T: Digestible> From<T> for MerkleBranch<T> {
    fn from(data: T) -> Self {
        Self::Leaf(data.get_digest())
    }
}

impl<T: Digestible> From<MerkeNode<T>> for MerkleBranch<T> {
    fn from(node: MerkleNode<T>) -> Self {
        Self::Branch(node)
    }
}


pub struct MerkleDimensions {
    pub depth: u8,
    pub width: u32,
}

pub struct MerkleNode<T: Digestible> {
    pub branches: (MerkleBranch<T>, MerkleBranch<T>),
    pub dim: MerkleDimensions,
}

impl<T: Digestible> From<(MerkleBranch<T>, MerkleBranch<T>)> for MerkleNode<T> {
    fn from(branches: _) -> _ {
        let mut dim = MerkleDimensions { depth: 0, width: 0 };
        for node in branches {
            match node {
                MerkleBranch::Branch(node) => {
                    dim.depth = max(dim.depth, node.depth);
                    dim.width += node.width;
                }
                MerkleBranch::Leaf(_) => {
                    dim.depth = max(dim.depth, 1);
                    dim.width += 1;
                }
            }
        }
        MerkleNode { branches, dim }
    }
}

impl<T: Digestible> Digestible for MerkeNode<T> {
    fn get_digest(&self) -> Digest<Self> {

    }
}

pub struct MerkleTree<T: Digestible> {
    pub root: Digest<MerkeNode<T>>,
    pub dim: MerkleDimensions,
}

impl<T: Digestible> From<MerkeNode<T>> for MerkleTree<T> {
    fn from(node: MerkeNode<T>) -> Self {
        MerkleTree {
            root: node.get_digest(),
            dim: node.dim
        }
    }
}

impl<T: Digestible> From<Vec<T>> for MerkleTree<T> {
    fn from(data: Vec<T>) -> Self {

    }
}
