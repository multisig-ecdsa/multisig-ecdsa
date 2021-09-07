use curv_kzen::cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
use curv_kzen::cryptographic_primitives::commitments::traits::Commitment;
use curv_kzen::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv_kzen::cryptographic_primitives::hashing::traits::Hash;
use curv_kzen::elliptic::curves::secp256_k1::{FE, GE};
use curv_kzen::elliptic::curves::traits::{ECScalar, ECPoint};
use serde::{Serialize, Deserialize};
use crate::error::InvalidProof;

pub use crate::zero_knowledge::cl_zk_aff::ClassProofAffine;
pub use crate::zero_knowledge::cl_zk_enc::ClassProofEncrypt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitKnowledgeProof {
    com_mask: GE,
    msg_mask: FE,
    rnd_mask: FE
}

impl CommitKnowledgeProof {
    pub fn prove(com: &GE, msg: &FE, rnd: &FE) -> Self {
        let msg_rand = FE::new_random();
        let rnd_rand = FE::new_random();
        let com_mask = PedersenCommitment::<GE>::create_commitment_with_user_defined_randomness(&msg_rand.to_big_int(), &rnd_rand.to_big_int());
        let challenge: FE= ECScalar::from(&HSha256::create_hash(&[&com.bytes_compressed_to_big_int(), &com_mask.bytes_compressed_to_big_int()]));
        Self{
            com_mask: com_mask,
            msg_mask: msg_rand + challenge * msg,
            rnd_mask: rnd_rand + challenge * rnd
        }
    }
    
    pub fn verify(&self, com: &GE) -> Result<(), InvalidProof> {
        let challenge: FE= ECScalar::from(&HSha256::create_hash(&[&com.bytes_compressed_to_big_int(), &self.com_mask.bytes_compressed_to_big_int()]));
        if GE::generator() * self.msg_mask + GE::base_point2() * self.rnd_mask != self.com_mask + com * &challenge {
            return Err(InvalidProof);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitConsistentProof {
    val_mask: GE,
    com_mask: GE,
    msg_mask: FE,
    rnd_mask: FE
}

impl CommitConsistentProof {
    pub fn prove(base: &GE, val: &GE, com: &GE, msg: &FE, rnd: &FE) -> Self {
        let msg_rand = FE::new_random();
        let rnd_rand = FE::new_random();
        let val_mask = base * &msg_rand;
        let com_mask = PedersenCommitment::<GE>::create_commitment_with_user_defined_randomness(&msg_rand.to_big_int(), &rnd_rand.to_big_int());
        let challenge: FE= ECScalar::from(&HSha256::create_hash(&[
            &val.bytes_compressed_to_big_int(),
            &val_mask.bytes_compressed_to_big_int(),
            &com.bytes_compressed_to_big_int(),
            &com_mask.bytes_compressed_to_big_int()
        ]));
        Self{
            val_mask: val_mask,
            com_mask: com_mask,
            msg_mask: msg_rand + challenge * msg,
            rnd_mask: rnd_rand + challenge * rnd
        }
    }
    
    pub fn verify(&self, base: &GE, val: &GE, com: &GE) -> Result<(), InvalidProof> {
        let challenge: FE= ECScalar::from(&HSha256::create_hash(&[
            &val.bytes_compressed_to_big_int(),
            &self.val_mask.bytes_compressed_to_big_int(),
            &com.bytes_compressed_to_big_int(),
            &self.com_mask.bytes_compressed_to_big_int()
        ]));
        if base * &self.msg_mask != self.val_mask + val * &challenge {
            return Err(InvalidProof);
        }
        if GE::generator() * self.msg_mask + GE::base_point2() * self.rnd_mask != self.com_mask + com * &challenge {
            return Err(InvalidProof);
        }
        Ok(())
    }
}