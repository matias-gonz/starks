use crate::field::FieldElement;
use rs_merkle::algorithms::Sha256;
use rs_merkle::{self, Hasher};

#[derive(Clone)]
pub struct MerkleTree {
    inner: rs_merkle::MerkleTree<rs_merkle::algorithms::Sha256>,
}

impl MerkleTree {
    pub fn new(data: Vec<FieldElement>) -> MerkleTree {
        let hashed_data: Vec<[u8; 32]> = data
            .into_iter()
            .map(|d| Sha256::hash(&d.0.to_be_bytes()))
            .collect();

        let inner =
            rs_merkle::MerkleTree::<rs_merkle::algorithms::Sha256>::from_leaves(&hashed_data);

        MerkleTree { inner }
    }

    pub fn root(&self) -> String {
        self.inner.root_hex().unwrap()
    }

    pub fn get_authentication_path(&self, idx: usize) -> String {
        let proof = self.inner.proof(&[idx]);
        proof
            .proof_hashes_hex()
            .iter()
            .fold(String::new(), |h1, h2| h1 + h2)
    }
}
