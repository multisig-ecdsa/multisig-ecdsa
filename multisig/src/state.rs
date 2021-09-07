use serde::{Serialize, Deserialize};
use curv_kzen::elliptic::curves::secp256_k1::{FE, GE};
use class_group::primitives::cl_dl_public_setup;
use curv_kzen::BigInt;

use crate::message::{MultisigMessageMtaTrans};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStateShare {
    pub (crate) clgroup: cl_dl_public_setup::CLGroup,
    pub (crate) clpk: Vec<cl_dl_public_setup::PK>,
    pub (crate) clsk: cl_dl_public_setup::SK,
    pub (crate) sets: Vec<GE>,
    pub (crate) sk: FE,
    pub (crate) member_number: usize,
    pub (crate) index: usize,
    pub (crate) k: FE,
    pub (crate) gamma: FE,
    pub (crate) message: Vec<u8>,
    pub (crate) message_hash: FE
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase1;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase1Sent {
    pub (crate) dec_gamma_pow: BigInt
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase2 {
    pub (crate) dec_gamma_pow: BigInt,
    pub (crate) com_gamma_pow_list: Vec<BigInt>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase2Sent {
    pub (crate) mta_init_random: cl_dl_public_setup::SK,
    pub (crate) dec_gamma_pow: BigInt,
    pub (crate) com_gamma_pow_list: Vec<BigInt>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase2ReceivedInit {
    pub (crate) dec_gamma_pow: BigInt,
    pub (crate) com_gamma_pow_list: Vec<BigInt>,
    pub (crate) mta_init_ciphertext: Vec<cl_dl_public_setup::Ciphertext>,
    pub (crate) mta_init_random: cl_dl_public_setup::SK,
    pub (crate) mta_share_beta: Vec<FE>,
    pub (crate) mta_trans_message: Vec<MultisigMessageMtaTrans>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase2SentTrans {
    pub (crate) dec_gamma_pow: BigInt,
    pub (crate) com_gamma_pow_list: Vec<BigInt>,
    pub (crate) mta_init_ciphertext: Vec<cl_dl_public_setup::Ciphertext>,
    pub (crate) mta_init_random: cl_dl_public_setup::SK,
    pub (crate) mta_share_beta: Vec<FE>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase3 {
    pub (crate) dec_gamma_pow: BigInt,
    pub (crate) com_gamma_pow_list: Vec<BigInt>,
    pub (crate) mta_init_ciphertext: Vec<cl_dl_public_setup::Ciphertext>,
    pub (crate) mta_init_random: cl_dl_public_setup::SK,
    pub (crate) mta_share_alpha: Vec<FE>,
    pub (crate) mta_share_beta: Vec<FE>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase4 {
    pub (crate) dec_gamma_pow: BigInt,
    pub (crate) com_gamma_pow_list: Vec<BigInt>,
    pub (crate) mta_init_ciphertext: Vec<cl_dl_public_setup::Ciphertext>,
    pub (crate) mta_init_random: cl_dl_public_setup::SK,
    pub (crate) mta_share_alpha: Vec<FE>,
    pub (crate) mta_share_beta: Vec<FE>,
    pub (crate) delta_share: Vec<FE>,
    pub (crate) delta: FE
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase5 {
    pub (crate) gamma_pow_list: Vec<GE>,
    pub (crate) mta_init_ciphertext: Vec<cl_dl_public_setup::Ciphertext>,
    pub (crate) mta_init_random: cl_dl_public_setup::SK,
    pub (crate) mta_share_alpha: Vec<FE>,
    pub (crate) mta_share_beta: Vec<FE>,
    pub (crate) delta_share: Vec<FE>,
    pub (crate) delta: FE,
    pub (crate) r_point: GE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase5Sent {
    pub (crate) gamma_pow_list: Vec<GE>,
    pub (crate) mta_init_ciphertext: Vec<cl_dl_public_setup::Ciphertext>,
    pub (crate) mta_share_alpha: Vec<FE>,
    pub (crate) mta_share_beta: Vec<FE>,
    pub (crate) delta_share: Vec<FE>,
    pub (crate) delta: FE,
    pub (crate) r_point: GE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase6 {
    pub (crate) gamma_pow_list: Vec<GE>,
    pub (crate) mta_init_ciphertext: Vec<cl_dl_public_setup::Ciphertext>,
    pub (crate) mta_share_alpha: Vec<FE>,
    pub (crate) mta_share_beta: Vec<FE>,
    pub (crate) mta_share_nu: Vec<FE>,
    pub (crate) delta_share: Vec<FE>,
    pub (crate) delta: FE,
    pub (crate) r_point: GE,
    pub (crate) mta_trans_message: Vec<MultisigMessageMtaTrans>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase6Sent {
    pub (crate) gamma_pow_list: Vec<GE>,
    pub (crate) mta_init_ciphertext: Vec<cl_dl_public_setup::Ciphertext>,
    pub (crate) mta_share_alpha: Vec<FE>,
    pub (crate) mta_share_beta: Vec<FE>,
    pub (crate) mta_share_nu: Vec<FE>,
    pub (crate) delta_share: Vec<FE>,
    pub (crate) delta: FE,
    pub (crate) r_point: GE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase7 {
    pub (crate) gamma_pow_list: Vec<GE>,
    pub (crate) mta_init_ciphertext: Vec<cl_dl_public_setup::Ciphertext>,
    pub (crate) mta_share_alpha: Vec<FE>,
    pub (crate) mta_share_beta: Vec<FE>,
    pub (crate) mta_share_mu: Vec<FE>,
    pub (crate) mta_share_nu: Vec<FE>,
    pub (crate) delta_share: Vec<FE>,
    pub (crate) delta: FE,
    pub (crate) sigma_share: FE,
    pub (crate) r_point: GE,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase7Sent {
    pub (crate) dec_sigma_share: BigInt,
    pub (crate) gamma_pow_list: Vec<GE>,
    pub (crate) mta_init_ciphertext: Vec<cl_dl_public_setup::Ciphertext>,
    pub (crate) mta_share_alpha: Vec<FE>,
    pub (crate) mta_share_beta: Vec<FE>,
    pub (crate) mta_share_mu: Vec<FE>,
    pub (crate) mta_share_nu: Vec<FE>,
    pub (crate) delta_share: Vec<FE>,
    pub (crate) delta: FE,
    pub (crate) sigma_share: FE,
    pub (crate) r_point: GE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase8 {
    pub (crate) com_sigma_share_list: Vec<GE>,
    pub (crate) dec_sigma_share: BigInt,
    pub (crate) sigma_share: FE,
    pub (crate) gamma_pow_list: Vec<GE>,
    pub (crate) mta_init_ciphertext: Vec<cl_dl_public_setup::Ciphertext>,
    pub (crate) mta_share_alpha: Vec<FE>,
    pub (crate) mta_share_beta: Vec<FE>,
    pub (crate) mta_share_mu: Vec<FE>,
    pub (crate) mta_share_nu: Vec<FE>,
    pub (crate) delta_share: Vec<FE>,
    pub (crate) delta: FE,
    pub (crate) r_point: GE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigStatePhase9 {
    pub (crate) com_sigma_share_list: Vec<GE>,
    pub (crate) dec_sigma_share: BigInt,
    pub (crate) sigma_share: FE,
    pub (crate) gamma_pow_list: Vec<GE>,
    pub (crate) mta_init_ciphertext: Vec<cl_dl_public_setup::Ciphertext>,
    pub (crate) mta_share_alpha: Vec<FE>,
    pub (crate) mta_share_beta: Vec<FE>,
    pub (crate) mta_share_mu: Vec<FE>,
    pub (crate) mta_share_nu: Vec<FE>,
    pub (crate) delta_share: Vec<FE>,
    pub (crate) delta: FE,
    pub (crate) r_point: GE,
    pub (crate) r_coor: FE
}