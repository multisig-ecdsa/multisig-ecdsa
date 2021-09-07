use serde::{Serialize, Deserialize};
use curv_kzen::BigInt;
use curv_kzen::elliptic::curves::secp256_k1::{FE, GE};
use class_group::primitives::cl_dl_public_setup::{Ciphertext};

use crate::proof::*;
use crate::mta::{MtaProofInit, MtaProofTrans};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageList<T> {
    pub message_list: Vec<T>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigMessageHashCommit {
    pub (crate) com_gamma_pow: BigInt
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigMessageMtaInit {
    pub (crate) mta_init_ciphertext: Ciphertext,
    pub (crate) mta_init_proof: MtaProofInit
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigMessageMtaTrans {
    pub (crate) mta_trans_ciphertext: Ciphertext,
    pub (crate) mta_trans_proof: MtaProofTrans
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigMessageShareDelta {
    pub (crate) delta_share: FE
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigMessageHashDecomit {
    pub (crate) dec_gamma_pow: BigInt,
    pub (crate) gamma_pow: GE
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigMessageRConsistent {
    pub (crate) r_bar: GE,
    pub (crate) consistency_proof: ClassProofEncrypt
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigMessageSigmaCommit {
    pub (crate) commitment: GE,
    pub (crate) proof: CommitKnowledgeProof
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigMessageSigmaConsistent {
    pub (crate) s_point: GE,
    pub (crate) proof: CommitConsistentProof
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigMessageSShare {
    pub (crate) s_share: FE
}