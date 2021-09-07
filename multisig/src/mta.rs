use curv_kzen::elliptic::curves::secp256_k1::{FE, GE};
use curv_kzen::elliptic::curves::traits::ECScalar;
use class_group::primitives::cl_dl_public_setup;
use class_group::primitives::cl_dl_public_setup::{CLGroup, PK, SK, Ciphertext};
use serde::{Serialize, Deserialize};
use crate::error::InvalidProof;
use crate::zero_knowledge::cl_zk_aff::ClassProofAffine;
use crate::zero_knowledge::cl_zk_enc::ClassProofEncrypt;

pub type MtaShare1 = FE;
pub type MtaShare2 = FE;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaProofInit {
    pub (crate) binding: GE,
    pub (crate) proof: ClassProofEncrypt
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaProofTrans {
    pub (crate) binding: GE,
    pub (crate) proof: ClassProofAffine
}


pub fn mta_encrypt(clgroup: &CLGroup, sk: &SK, pk: &PK, msg: &FE, bind_base: &GE) -> (Ciphertext, SK, MtaProofInit){
    let (c, aux) = cl_dl_public_setup::encrypt(clgroup, pk, msg);
    let binding = bind_base * msg;
    let pi = MtaProofInit{
        binding,
        proof: ClassProofEncrypt::prove(
            clgroup,
            pk,
            sk,
            &msg.to_big_int(),
            &aux.0,
            &bind_base
        )
    };
    (c, aux, pi)
}

pub fn mta_transform(clgroup: &CLGroup, pk: &PK, msg: &FE, c: &Ciphertext, proof: Option<&MtaProofInit>, bind_base: &GE) -> Result<(MtaShare2, Ciphertext, MtaProofTrans), InvalidProof>{
    if proof.is_some() && proof.unwrap().verify().is_err() {
        return Err(InvalidProof);
    }
    let share2 = FE::new_random();
    let share2_minus = FE::zero().sub(&share2.get_element());
    let (c_share, aux_share) = cl_dl_public_setup::encrypt(clgroup, pk, &share2_minus);
    let ciphertext = cl_dl_public_setup::eval_scal(c, &msg.to_big_int());
    let ciphertext = cl_dl_public_setup::eval_sum(&ciphertext, &c_share);
    let binding = bind_base * msg;
    let proof = MtaProofTrans {
        binding,
        proof: ClassProofAffine::prove(
            clgroup,
            pk,
            &share2_minus.to_big_int(),
            &aux_share.0,
            &msg.to_big_int(),
            &c,
            &bind_base
        )
    };
    Ok((share2, ciphertext, proof))
}

pub fn mta_decrypt(clgroup: &CLGroup, pk: &PK, sk: &SK, ciphertext_init: &Ciphertext, ciphertext_trans: &Ciphertext, proof: &MtaProofTrans, bind_base: &GE) -> Result<FE, InvalidProof>{
    if proof.verify(clgroup, pk, ciphertext_init, ciphertext_trans, bind_base).is_err() {
        return Err(InvalidProof);
    }
    let share1 = cl_dl_public_setup::decrypt(clgroup, sk, ciphertext_trans);
    Ok(share1)
}


impl MtaProofInit {
    pub fn verify(&self) -> Result<(), InvalidProof>{
        Ok(())
    }
}

impl MtaProofTrans {
    pub fn verify(&self, clgroup: &CLGroup, clpk: &PK, enc_init: &Ciphertext, enc_trans: &Ciphertext, bind_base: &GE) -> Result<(), InvalidProof> {
        if self.proof.verify(clgroup, clpk, enc_init, enc_trans, bind_base, &self.binding).is_err() {
            return Err(InvalidProof)
        }
        Ok(())
    }
}

#[cfg(test)]
mod test{
    use super::*;
    use curv_kzen::arithmetic::Samplable;
    use curv_kzen::BigInt;
    
    #[test]
    pub fn test_mta() {
        let group = cl_dl_public_setup::CLGroup::new_from_setup(&1600, &BigInt::sample(1024));
        let (sk, pk) = group.keygen();
        let a = FE::new_random();
        let b = FE::new_random();
        let base = GE::random_point();
        let (c1, _, proof1) = mta_encrypt(&group, &sk, &pk, &a, &base);
        let (s1, c2, proof2) = mta_transform(&group, &pk, &b, &c1, Some(&proof1), &base).unwrap();
        let s2 = mta_decrypt(&group, &pk, &sk, &c1, &c2, &proof2, &base).unwrap();
        assert_eq!(a * b, s1 + s2);
    }
}