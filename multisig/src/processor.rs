use serde::{Serialize, Deserialize};
use curv_kzen::BigInt;
use curv_kzen::arithmetic::{Converter};
use curv_kzen::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv_kzen::cryptographic_primitives::commitments::pedersen_commitment::PedersenCommitment;
use curv_kzen::cryptographic_primitives::commitments::traits::Commitment;
use curv_kzen::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv_kzen::cryptographic_primitives::hashing::traits::Hash;
use curv_kzen::elliptic::curves::secp256_k1::{FE, GE};
use curv_kzen::elliptic::curves::traits::{ECScalar, ECPoint};
use class_group::primitives::cl_dl_public_setup::{CLGroup, PK, SK};

use crate::error::MultisigAbort;
use crate::state::*;
use crate::message::*;
use crate::mta::*;
use crate::proof::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigProcessor<T> {
    share_state: MultisigStateShare,
    state: T
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigComplete {
    pub (crate) r_coor: FE,
    pub (crate) s: FE
}

pub trait TransitionSend<M, T> {
    fn send(self) -> (M, T);
}

pub trait TransitionReceive<M, T> {
    fn receive(self, msg: Vec<M>) -> Result<T, MultisigAbort>;
}

fn compute_sk_mask(index: usize, r_point: &GE, sets: &[GE], msg: &[u8]) -> FE{
    let mut concat_content = sets.iter().cloned().map(|each| each.bytes_compressed_to_big_int()).collect::<Vec::<_>>();
    concat_content.push(BigInt::from(index as u64));
    concat_content.push(r_point.bytes_compressed_to_big_int());
    concat_content.push(BigInt::from_bytes(msg));
    ECScalar::from(&HSha256::create_hash(&concat_content.iter().collect::<Vec::<_>>()))
}

fn accumulate_pk(r_point: &GE, sets: &[GE], msg: &[u8]) -> GE{
    (1..sets.len()).fold(
        sets[0] * compute_sk_mask(0, r_point, sets, msg),
        |acc, i| acc + sets[i] * compute_sk_mask(i, r_point, sets, msg)
    )
}

impl MultisigProcessor<MultisigStatePhase1> {
    pub fn init(clgroup: &CLGroup, clsk: &SK, clpk: &[PK], sk: &FE, sets: &[GE], index: usize, msg: &[u8]) -> Result<Self, MultisigAbort> {
        let member_number = clpk.len();
        if member_number != sets.len() {
            return Err(MultisigAbort);
        }
        Ok(Self {
            share_state: MultisigStateShare {
                clgroup: clgroup.clone(),
                clpk: Vec::from(clpk),
                clsk: clsk.clone(),
                sets: Vec::from(sets),
                sk: sk.clone(),
                member_number,
                index: index,
                k: FE::new_random(),
                gamma: FE::new_random(),
                message: Vec::from(msg),
                message_hash: ECScalar::from(&HSha256::create_hash_from_slice(&msg))
            },
            state: MultisigStatePhase1{}
        })
    }
}

impl TransitionSend<MultisigMessageHashCommit, MultisigProcessor<MultisigStatePhase1Sent>> for MultisigProcessor<MultisigStatePhase1> {
    fn send(self) -> (MultisigMessageHashCommit, MultisigProcessor<MultisigStatePhase1Sent>) {
        let gamma_pow = GE::generator() * self.share_state.gamma;
        let (com_gamma_pow, dec_gamma_pow) = HashCommitment::create_commitment(&gamma_pow.bytes_compressed_to_big_int());
        let message = MultisigMessageHashCommit {
            com_gamma_pow
        };
        let next = MultisigProcessor::<MultisigStatePhase1Sent> {
            share_state: self.share_state,
            state: MultisigStatePhase1Sent{
                dec_gamma_pow
            },
        };
        (message, next)
    }
}

impl TransitionReceive<MultisigMessageHashCommit, MultisigProcessor<MultisigStatePhase2>> for MultisigProcessor<MultisigStatePhase1Sent> {
    fn receive(self, msg: Vec<MultisigMessageHashCommit>) -> Result<MultisigProcessor<MultisigStatePhase2>, MultisigAbort> {
        if self.share_state.member_number != msg.len() {
            return Err(MultisigAbort);
        }
        Ok(MultisigProcessor::<MultisigStatePhase2> {
            share_state: self.share_state,
            state: MultisigStatePhase2{
                dec_gamma_pow: self.state.dec_gamma_pow,
                com_gamma_pow_list: msg.into_iter().map(|m| m.com_gamma_pow).collect()
            }
        })
    }
}

impl TransitionSend<MultisigMessageMtaInit, MultisigProcessor<MultisigStatePhase2Sent>> for MultisigProcessor<MultisigStatePhase2> {
    fn send(self) -> (MultisigMessageMtaInit, MultisigProcessor<MultisigStatePhase2Sent>) {
        let (mta_ciphertext, mta_init_random, mta_proof) = mta_encrypt(
            &self.share_state.clgroup,
            &self.share_state.clsk,
            &self.share_state.clpk[self.share_state.index],
            &self.share_state.k,
            &GE::generator()
        );
        let message = MultisigMessageMtaInit {
            mta_init_ciphertext: mta_ciphertext,
            mta_init_proof: mta_proof
        };
        (message, MultisigProcessor::<MultisigStatePhase2Sent> {
            share_state: self.share_state,
            state: MultisigStatePhase2Sent{
                dec_gamma_pow: self.state.dec_gamma_pow,
                com_gamma_pow_list: self.state.com_gamma_pow_list,
                mta_init_random: mta_init_random
            }
        })
    }
}

impl TransitionReceive<MultisigMessageMtaInit, MultisigProcessor<MultisigStatePhase2ReceivedInit>> for MultisigProcessor<MultisigStatePhase2Sent> {
    fn receive(self, msg: Vec<MultisigMessageMtaInit>) -> Result<MultisigProcessor<MultisigStatePhase2ReceivedInit>, MultisigAbort> {
        let n = self.share_state.member_number;
        if n != msg.len() {
            return Err(MultisigAbort);
        }
        let mut mta_share_beta = Vec::<FE>::new();
        let mut mta_trans_message = Vec::<MultisigMessageMtaTrans>::with_capacity(n);
        for i in 0..n {
            let trans_result = mta_transform(
                &self.share_state.clgroup,
                &self.share_state.clpk[i],
                &self.share_state.gamma,
                &msg[i].mta_init_ciphertext,
                Some(&msg[i].mta_init_proof),
                &GE::generator()
            );
            if trans_result.is_err() {
                return Err(MultisigAbort);
            }
            let (share, cipher, proof) = trans_result.unwrap();
            mta_share_beta.push(share);
            mta_trans_message.push(MultisigMessageMtaTrans{
                mta_trans_ciphertext: cipher,
                mta_trans_proof: proof
            });
        }
        Ok(MultisigProcessor::<MultisigStatePhase2ReceivedInit> {
            share_state: self.share_state,
            state: MultisigStatePhase2ReceivedInit {
                dec_gamma_pow: self.state.dec_gamma_pow,
                com_gamma_pow_list: self.state.com_gamma_pow_list,
                mta_init_random: self.state.mta_init_random,
                mta_init_ciphertext: msg.into_iter().map(|each| each.mta_init_ciphertext).collect(),
                mta_share_beta: mta_share_beta,
                mta_trans_message: mta_trans_message,
            }
        })
    }
}

impl TransitionSend<MessageList<MultisigMessageMtaTrans>, MultisigProcessor<MultisigStatePhase2SentTrans>> for MultisigProcessor<MultisigStatePhase2ReceivedInit> {
    fn send(self) -> (MessageList<MultisigMessageMtaTrans>, MultisigProcessor<MultisigStatePhase2SentTrans>) {
        (
            MessageList::<MultisigMessageMtaTrans> {
                message_list: self.state.mta_trans_message,
            },
            MultisigProcessor::<MultisigStatePhase2SentTrans> {
                share_state: self.share_state,
                state: MultisigStatePhase2SentTrans {
                    dec_gamma_pow: self.state.dec_gamma_pow,
                    com_gamma_pow_list: self.state.com_gamma_pow_list,
                    mta_init_random: self.state.mta_init_random,
                    mta_init_ciphertext: self.state.mta_init_ciphertext,
                    mta_share_beta: self.state.mta_share_beta,
                }
            }
        )
    }
}

impl TransitionReceive<MultisigMessageMtaTrans, MultisigProcessor<MultisigStatePhase3>> for MultisigProcessor<MultisigStatePhase2SentTrans> {
    fn receive(self, msg: Vec<MultisigMessageMtaTrans>) -> Result<MultisigProcessor<MultisigStatePhase3>, MultisigAbort> {
        let n = self.share_state.member_number;
        if n != msg.len() {
            return Err(MultisigAbort);
        }
        let mut mta_share_alpha = Vec::<FE>::with_capacity(n);
        for i in 0..n {
            let decrypt_result = mta_decrypt(
                &self.share_state.clgroup,
                &self.share_state.clpk[self.share_state.index],
                &self.share_state.clsk,
                &self.state.mta_init_ciphertext[self.share_state.index],
                &msg[i].mta_trans_ciphertext,
                &msg[i].mta_trans_proof,
                &GE::generator()
            );
            if decrypt_result.is_err() {
                return Err(MultisigAbort);
            }
            mta_share_alpha.push(decrypt_result.unwrap());
        }
        Ok(MultisigProcessor::<MultisigStatePhase3> {
            share_state: self.share_state,
            state: MultisigStatePhase3 {
                dec_gamma_pow: self.state.dec_gamma_pow,
                com_gamma_pow_list: self.state.com_gamma_pow_list,
                mta_init_random: self.state.mta_init_random,
                mta_init_ciphertext: self.state.mta_init_ciphertext,
                mta_share_alpha: mta_share_alpha,
                mta_share_beta: self.state.mta_share_beta,
            }
        })
    }
}

impl TransitionSend<MultisigMessageShareDelta, MultisigProcessor<MultisigStatePhase3>> for MultisigProcessor<MultisigStatePhase3> {
    fn send(self) -> (MultisigMessageShareDelta, MultisigProcessor<MultisigStatePhase3>) {
        (
            MultisigMessageShareDelta{
                delta_share: (1..self.share_state.member_number)
                    .fold(self.state.mta_share_alpha[0] + self.state.mta_share_beta[0],
                        |sum, i| sum + self.state.mta_share_alpha[i] + self.state.mta_share_beta[i]
                    )
            },
            self
        )
    }
}

impl TransitionReceive<MultisigMessageShareDelta, MultisigProcessor<MultisigStatePhase4>> for MultisigProcessor<MultisigStatePhase3> {
    fn receive(self, msg: Vec<MultisigMessageShareDelta>) -> Result<MultisigProcessor<MultisigStatePhase4>, MultisigAbort> {
        let n = self.share_state.member_number;
        if n != msg.len() {
            return Err(MultisigAbort);
        }
        let delta = (1..n).fold(msg[0].delta_share, |acc, i| acc + msg[i].delta_share);
        Ok(MultisigProcessor::<MultisigStatePhase4> {
            share_state: self.share_state,
            state: MultisigStatePhase4 {
                dec_gamma_pow: self.state.dec_gamma_pow,
                com_gamma_pow_list: self.state.com_gamma_pow_list,
                mta_init_random: self.state.mta_init_random,
                mta_init_ciphertext: self.state.mta_init_ciphertext,
                mta_share_alpha: self.state.mta_share_alpha,
                mta_share_beta: self.state.mta_share_beta,
                delta_share: msg.into_iter().map(|m| m.delta_share).collect(),
                delta: delta
            }
        })
    }
}

impl TransitionSend<MultisigMessageHashDecomit, MultisigProcessor<MultisigStatePhase4>> for MultisigProcessor<MultisigStatePhase4> {
    fn send(self) -> (MultisigMessageHashDecomit, MultisigProcessor<MultisigStatePhase4>) {
        let message = MultisigMessageHashDecomit {
            dec_gamma_pow: self.state.dec_gamma_pow.clone(),
            gamma_pow: GE::generator() * self.share_state.gamma
        };
        (message, self)
    }
}

impl TransitionReceive<MultisigMessageHashDecomit, MultisigProcessor<MultisigStatePhase5>> for MultisigProcessor<MultisigStatePhase4> {
    fn receive(self, msg: Vec<MultisigMessageHashDecomit>) -> Result<MultisigProcessor<MultisigStatePhase5>, MultisigAbort> {
        let n = self.share_state.member_number;
        if n != msg.len() {
            return Err(MultisigAbort);
        }
        for i in 0..n {
            let recom = HashCommitment::create_commitment_with_user_defined_randomness(&msg[i].gamma_pow.bytes_compressed_to_big_int(), &msg[i].dec_gamma_pow);
            if recom != self.state.com_gamma_pow_list[i] {
                return Err(MultisigAbort)
            }
        }
        let r_point = (1..n).fold(msg[0].gamma_pow.clone(), |sum, i| sum + msg[i].gamma_pow.clone()) * (self.state.delta.invert());
        Ok(MultisigProcessor::<MultisigStatePhase5> {
            share_state: self.share_state,
            state: MultisigStatePhase5 {
                gamma_pow_list: msg.into_iter().map(|each| each.gamma_pow).collect(),
                mta_init_random: self.state.mta_init_random,
                mta_init_ciphertext: self.state.mta_init_ciphertext,
                mta_share_alpha: self.state.mta_share_alpha,
                mta_share_beta: self.state.mta_share_beta,
                delta_share: self.state.delta_share,
                delta: self.state.delta,
                r_point: r_point
            }
        })
    }
}

impl TransitionSend<MultisigMessageRConsistent, MultisigProcessor<MultisigStatePhase5Sent>> for MultisigProcessor<MultisigStatePhase5> {
    fn send(self) -> (MultisigMessageRConsistent, MultisigProcessor<MultisigStatePhase5Sent>) {
        let r_bar = self.state.r_point * self.share_state.k;
        let message = MultisigMessageRConsistent {
            r_bar: r_bar,
            consistency_proof: ClassProofEncrypt::prove(
                &self.share_state.clgroup,
                &self.share_state.clpk[self.share_state.index],
                &self.share_state.clsk,
                &self.share_state.k.to_big_int(),
                &self.state.mta_init_random.0,
                &self.state.r_point
            )
        };
        (message, MultisigProcessor::<MultisigStatePhase5Sent> {
            share_state: self.share_state,
            state: MultisigStatePhase5Sent {
                gamma_pow_list: self.state.gamma_pow_list,
                mta_init_ciphertext: self.state.mta_init_ciphertext,
                mta_share_alpha: self.state.mta_share_alpha,
                mta_share_beta: self.state.mta_share_beta,
                delta_share: self.state.delta_share,
                delta: self.state.delta,
                r_point: self.state.r_point
            }
        })
    }
}

impl TransitionReceive<MultisigMessageRConsistent, MultisigProcessor<MultisigStatePhase6>> for MultisigProcessor<MultisigStatePhase5Sent> {
    fn receive(self, msg: Vec<MultisigMessageRConsistent>) -> Result<MultisigProcessor<MultisigStatePhase6>, MultisigAbort> {
        let n = self.share_state.member_number;
        if n != msg.len() {
            return Err(MultisigAbort);
        }
        for i in 0..n {
            if msg[i].consistency_proof.verify(
                &self.share_state.clgroup,
                &self.share_state.clpk[i],
                &self.state.mta_init_ciphertext[i],
                &self.state.r_point,
                &msg[i].r_bar
            ).is_err() {
                return Err(MultisigAbort);
            }
        }
        let acc_r_bar = (1..n).fold(msg[0].r_bar, |acc, i| acc + msg[i].r_bar);
        if acc_r_bar != GE::generator() {
            return Err(MultisigAbort);
        }
        let ax = compute_sk_mask(self.share_state.index, &self.state.r_point, &self.share_state.sets, &self.share_state.message) * self.share_state.sk;
        let mut mta_trans_message = Vec::<MultisigMessageMtaTrans>::with_capacity(n);
        let mut mta_share_nu = Vec::<FE>::with_capacity(n);
        for i in 0..n {
            let trans_result = mta_transform(
                &self.share_state.clgroup,
                &self.share_state.clpk[i],
                &ax,
                &self.state.mta_init_ciphertext[i],
                None,
                &GE::generator()
            );
            if trans_result.is_err() {
                return Err(MultisigAbort);
            }
            let (share, cipher, proof) = trans_result.unwrap();
            mta_share_nu.push(share);
            mta_trans_message.push(MultisigMessageMtaTrans{
                mta_trans_ciphertext: cipher,
                mta_trans_proof: proof
            });
        }
        Ok(MultisigProcessor::<MultisigStatePhase6> {
            share_state: self.share_state,
            state: MultisigStatePhase6 {
                gamma_pow_list: self.state.gamma_pow_list,
                mta_init_ciphertext: self.state.mta_init_ciphertext,
                mta_share_alpha: self.state.mta_share_alpha,
                mta_share_beta: self.state.mta_share_beta,
                mta_share_nu: mta_share_nu,
                mta_trans_message: mta_trans_message,
                delta_share: self.state.delta_share,
                delta: self.state.delta,
                r_point: self.state.r_point
            }
        })
    }
}

impl TransitionSend<MessageList<MultisigMessageMtaTrans>, MultisigProcessor<MultisigStatePhase6Sent>> for MultisigProcessor<MultisigStatePhase6> {
    fn send(self) -> (MessageList<MultisigMessageMtaTrans>, MultisigProcessor<MultisigStatePhase6Sent>) {
        let message = MessageList::<MultisigMessageMtaTrans> {
            message_list: self.state.mta_trans_message,
        };
        let state = MultisigProcessor::<MultisigStatePhase6Sent> {
            share_state: self.share_state,
            state: MultisigStatePhase6Sent {
                gamma_pow_list: self.state.gamma_pow_list,
                mta_init_ciphertext: self.state.mta_init_ciphertext,
                mta_share_alpha: self.state.mta_share_alpha,
                mta_share_beta: self.state.mta_share_beta,
                mta_share_nu: self.state.mta_share_nu,
                delta_share: self.state.delta_share,
                delta: self.state.delta,
                r_point: self.state.r_point
            }
        };
        (message, state)
    }
}

impl TransitionReceive<MultisigMessageMtaTrans, MultisigProcessor<MultisigStatePhase7>> for MultisigProcessor<MultisigStatePhase6Sent> {
    fn receive(self, msg: Vec<MultisigMessageMtaTrans>) -> Result<MultisigProcessor<MultisigStatePhase7>, MultisigAbort> {
        let n = self.share_state.member_number;
        if n != msg.len() {
            return Err(MultisigAbort);
        }
        let mut mta_share_mu = Vec::<FE>::with_capacity(n);
        for i in 0..n {
            let decrypt_result = mta_decrypt(
                &self.share_state.clgroup,
                &self.share_state.clpk[self.share_state.index],
                &self.share_state.clsk,
                &self.state.mta_init_ciphertext[self.share_state.index],
                &msg[i].mta_trans_ciphertext,
                &msg[i].mta_trans_proof,
                &GE::generator()
            );
            if decrypt_result.is_err() {
                return Err(MultisigAbort);
            }
            mta_share_mu.push(decrypt_result.unwrap());
        }
        let sigma_share = (1..n).fold(mta_share_mu[0] + self.state.mta_share_nu[0], |sum, i| sum + mta_share_mu[i] + self.state.mta_share_nu[i]);
        Ok(MultisigProcessor::<MultisigStatePhase7> {
            share_state: self.share_state,
            state: MultisigStatePhase7 {
                gamma_pow_list: self.state.gamma_pow_list,
                mta_init_ciphertext: self.state.mta_init_ciphertext,
                mta_share_alpha: self.state.mta_share_alpha,
                mta_share_beta: self.state.mta_share_beta,
                mta_share_mu: mta_share_mu,
                mta_share_nu: self.state.mta_share_nu,
                delta_share: self.state.delta_share,
                delta: self.state.delta,
                sigma_share: sigma_share,
                r_point: self.state.r_point
            }
        })
    }
}

impl TransitionSend<MultisigMessageSigmaCommit, MultisigProcessor<MultisigStatePhase7Sent>> for MultisigProcessor<MultisigStatePhase7> {
    fn send(self) -> (MultisigMessageSigmaCommit, MultisigProcessor<MultisigStatePhase7Sent>) {
        let (com, dec) = PedersenCommitment::<GE>::create_commitment(&self.state.sigma_share.to_big_int());
        let message = MultisigMessageSigmaCommit {
            commitment: com,
            proof: CommitKnowledgeProof::prove(&com, &self.state.sigma_share, &ECScalar::from(&dec))
        };
        let state = MultisigProcessor::<MultisigStatePhase7Sent> {
            share_state: self.share_state,
            state: MultisigStatePhase7Sent {
                gamma_pow_list: self.state.gamma_pow_list,
                mta_init_ciphertext: self.state.mta_init_ciphertext,
                mta_share_alpha: self.state.mta_share_alpha,
                mta_share_beta: self.state.mta_share_beta,
                mta_share_mu: self.state.mta_share_mu,
                mta_share_nu: self.state.mta_share_nu,
                delta_share: self.state.delta_share,
                delta: self.state.delta,
                sigma_share: self.state.sigma_share,
                r_point: self.state.r_point,
                dec_sigma_share: dec
            }
        };
        (message, state)
    }
}

impl TransitionReceive<MultisigMessageSigmaCommit, MultisigProcessor<MultisigStatePhase8>> for MultisigProcessor<MultisigStatePhase7Sent> {
    fn receive(self, msg: Vec<MultisigMessageSigmaCommit>) -> Result<MultisigProcessor<MultisigStatePhase8>, MultisigAbort> {
        let n = self.share_state.member_number;
        if n != msg.len() {
            return Err(MultisigAbort);
        };
        for i in 0..n {
            if msg[i].proof.verify(&msg[i].commitment).is_err() {
                return Err(MultisigAbort);
            }
        }
        Ok(MultisigProcessor::<MultisigStatePhase8> {
            share_state: self.share_state,
            state: MultisigStatePhase8 {
                gamma_pow_list: self.state.gamma_pow_list,
                mta_init_ciphertext: self.state.mta_init_ciphertext,
                mta_share_alpha: self.state.mta_share_alpha,
                mta_share_beta: self.state.mta_share_beta,
                mta_share_mu: self.state.mta_share_mu,
                mta_share_nu: self.state.mta_share_nu,
                delta_share: self.state.delta_share,
                delta: self.state.delta,
                sigma_share: self.state.sigma_share,
                r_point: self.state.r_point,
                com_sigma_share_list: msg.into_iter().map(|each| each.commitment).collect(),
                dec_sigma_share: self.state.dec_sigma_share
            }
        })
    }
}

impl TransitionSend<MultisigMessageSigmaConsistent, MultisigProcessor<MultisigStatePhase8>> for MultisigProcessor<MultisigStatePhase8> {
    fn send(self) -> (MultisigMessageSigmaConsistent, MultisigProcessor<MultisigStatePhase8>) {
        let s_point = self.state.r_point * self.state.sigma_share;
        let message = MultisigMessageSigmaConsistent {
            s_point: s_point,
            proof: CommitConsistentProof::prove(
                &self.state.r_point,
                &s_point,
                &self.state.com_sigma_share_list[self.share_state.index],
                &self.state.sigma_share,
                &ECScalar::from(&self.state.dec_sigma_share)
            )
        };
        (message, self)
    }
}

impl TransitionReceive<MultisigMessageSigmaConsistent, MultisigProcessor<MultisigStatePhase9>> for MultisigProcessor<MultisigStatePhase8> {
    fn receive(self, msg: Vec<MultisigMessageSigmaConsistent>) -> Result<MultisigProcessor<MultisigStatePhase9>, MultisigAbort> {
        let n = self.share_state.member_number;
        if n != msg.len() {
            return Err(MultisigAbort);
        };
        for i in 0..n {
            if msg[i].proof.verify(
                &self.state.r_point,
                &msg[i].s_point,
                &self.state.com_sigma_share_list[i]
            ).is_err() {
                return Err(MultisigAbort);
            }
        }
        let r_coor: FE = ECScalar::from(&self.state.r_point.x_coor().unwrap());
        Ok(MultisigProcessor::<MultisigStatePhase9> {
            share_state: self.share_state,
            state: MultisigStatePhase9 {
                gamma_pow_list: self.state.gamma_pow_list,
                mta_init_ciphertext: self.state.mta_init_ciphertext,
                mta_share_alpha: self.state.mta_share_alpha,
                mta_share_beta: self.state.mta_share_beta,
                mta_share_mu: self.state.mta_share_mu,
                mta_share_nu: self.state.mta_share_nu,
                delta_share: self.state.delta_share,
                delta: self.state.delta,
                sigma_share: self.state.sigma_share,
                r_point: self.state.r_point,
                r_coor: r_coor,
                com_sigma_share_list: self.state.com_sigma_share_list,
                dec_sigma_share: self.state.dec_sigma_share
            }
        })
    }
}


impl TransitionSend<MultisigMessageSShare, MultisigProcessor<MultisigStatePhase9>> for MultisigProcessor<MultisigStatePhase9> {
    fn send(self) -> (MultisigMessageSShare, MultisigProcessor<MultisigStatePhase9>) {
        let message = MultisigMessageSShare {
            s_share: self.share_state.k * self.share_state.message_hash + self.state.sigma_share * self.state.r_coor
        };
        (message, self)
    }
}

impl TransitionReceive<MultisigMessageSShare, MultisigComplete> for MultisigProcessor<MultisigStatePhase9> {
    fn receive(self, msg: Vec<MultisigMessageSShare>) -> Result<MultisigComplete, MultisigAbort> {
        let n = self.share_state.member_number;
        if n != msg.len() {
            return Err(MultisigAbort);
        };
        let s = (1..n).fold(msg[0].s_share, |sum, i| sum + msg[i].s_share);
        let acc_pk = accumulate_pk(&self.state.r_point, &self.share_state.sets, &self.share_state.message);
        if self.state.r_point * s != GE::generator() * self.share_state.message_hash + acc_pk * self.state.r_coor{
            return Err(MultisigAbort);
        }
        Ok(MultisigComplete{
            r_coor: self.state.r_coor,
            s: s
        })
    }
}

#[cfg(test)]
mod test {
    use curv_kzen::BigInt;
    use super::*;
    // #[test]
    // fn test_secp256k1_from_bigint() {
    //     for _ in 0..100 {
    //         let point = GE::random_point();
    //         println!("x:{}", point.x_coor().unwrap().to_hex());
    //         println!("y:{}", point.y_coor().unwrap().to_hex());
    //         println!("recovered seq:{:x?}", point.bytes_compressed_to_big_int().to_bytes());
    //         assert_eq!(point, GE::from_bytes(&point.bytes_compressed_to_big_int().to_bytes()[1..33]).unwrap())
    //     }
    // }

    fn run_multisig(n: usize) {
        let clgroup = CLGroup::new_from_setup(&3392, &BigInt::from(100));
        let sk_list = (0..n).map(|_| FE::new_random()).collect::<Vec::<_>>();
        let pk_list = (0..n).map(|i| GE::generator() * sk_list[i]).collect::<Vec::<_>>();
        let mut clsk_list = Vec::<SK>::with_capacity(n);
        let mut clpk_list = Vec::<PK>::with_capacity(n);
        let message_sign = "test_message";
        for _ in 0..n {
            let (sk, pk) = clgroup.keygen();
            clsk_list.push(sk);
            clpk_list.push(pk);
        }
        let parties = (0..n).map(|i| MultisigProcessor::<MultisigStatePhase1>::init(
            &clgroup,
            &clsk_list[i],
            &clpk_list,
            &sk_list[i],
            &pk_list,
            i,
            &message_sign.as_bytes()
        ).unwrap()).collect::<Vec::<_>>();

        println!("Measurement for n = {}", n);
        println!("{:20} {:8}", "", "Time(ms)");

        //Phase1
        let now = cpu_time::ProcessTime::now();
        let (message, parties): (Vec<_>, Vec<_>) = parties.into_iter().map(|each| each.send()).unzip();
        let parties: Vec<_> = parties.into_iter().map(|each| each.receive(message.clone()).unwrap()).collect();
        let duration = (now.elapsed().as_micros() as f32) / (1000.0 * (n as f32));
        println!("{:20} {:8.2}", "Phase 1", duration);

        //Phase2
        let now = cpu_time::ProcessTime::now();
        let (message, parties): (Vec<_>, Vec<_>) = parties.into_iter().map(|each| each.send()).unzip();
        let parties: Vec<_> = parties.into_iter().map(|each| each.receive(message.clone()).unwrap()).collect();
        let duration = (now.elapsed().as_micros() as f32) / (1000.0 * (n as f32));
        println!("{:20} {:8.2}", "Phase 2 (part 1)", duration);

        let now = cpu_time::ProcessTime::now();
        let (message, parties): (Vec<_>, Vec<_>) = parties.into_iter().map(|each| each.send()).unzip();
        let mut redistributed_message = (0..n).map(|_| Vec::<MultisigMessageMtaTrans>::with_capacity(n)).collect::<Vec<_>>();
        for each in message.iter().cloned(){
            for (index, element) in each.message_list.into_iter().enumerate() {
                redistributed_message[index].push(element);
            }
        };
        let parties: Vec<_> = parties.into_iter().zip(redistributed_message.iter().cloned())
            .map(|(party, msg)| party.receive(msg).unwrap()).collect();
        let duration = (now.elapsed().as_micros() as f32) / (1000.0 * (n as f32));
        println!("{:20} {:8.2}", "Phase 2 (part 2)", duration);
        for i in 0..n {
            for j in 0..n {
                assert_eq!(parties[i].share_state.k * parties[j].share_state.gamma, parties[i].state.mta_share_alpha[j] + parties[j].state.mta_share_beta[i]);
            }
        }
        //Phase3
        let now = cpu_time::ProcessTime::now();
        let (message, parties): (Vec<_>, Vec<_>) = parties.into_iter().map(|each| each.send()).unzip();
        let parties: Vec<_> = parties.into_iter().map(|each| each.receive(message.clone()).unwrap()).collect();
        let duration = (now.elapsed().as_micros() as f32) / (1000.0 * (n as f32));
        println!("{:20} {:8.2}", "Phase 3", duration);

        let acc_k: FE = (1..n).fold(parties[0].share_state.k, |acc, i| acc + parties[i].share_state.k);
        let acc_gamma: FE = (1..n).fold(parties[0].share_state.gamma, |acc, i| acc + parties[i].share_state.gamma);
        let delta = acc_k * acc_gamma;
        for i in 0..n {
            assert_eq!(delta, parties[i].state.delta);
        }

        //Phase4
        let now = cpu_time::ProcessTime::now();
        let (message, parties): (Vec<_>, Vec<_>) = parties.into_iter().map(|each| each.send()).unzip();
        // let acc_gamma_pow = (1..n).fold(message[0].gamma_pow.clone(), |sum, i| sum + message[i].gamma_pow.clone());
        let parties: Vec<_> = parties.into_iter().map(|each| each.receive(message.clone()).unwrap()).collect();
        let duration = (now.elapsed().as_micros() as f32) / (1000.0 * (n as f32));
        println!("{:20} {:8.2}", "Phase 4", duration);
        for i in 0..n {
            for j in 0..n {
                assert_eq!(parties[i].state.gamma_pow_list[j], GE::generator() * parties[j].share_state.gamma);
            }
        }
        let r_point = GE::generator() * acc_k.invert();
        for i in 0..n {
            assert_eq!(r_point, parties[i].state.r_point);
        }

        //Phase5
        let now = cpu_time::ProcessTime::now();
        let (message, parties): (Vec<_>, Vec<_>) = parties.into_iter().map(|each| each.send()).unzip();
        let parties: Vec<_> = parties.into_iter().map(|each| each.receive(message.clone()).unwrap()).collect();
        let duration = (now.elapsed().as_micros() as f32) / (1000.0 * (n as f32));
        println!("{:20} {:8.2}", "Phase 5", duration);

        //Phase6
        let now = cpu_time::ProcessTime::now();
        let (message, parties): (Vec<_>, Vec<_>) = parties.into_iter().map(|each| each.send()).unzip();
        let mut redistributed_message = (0..n).map(|_| Vec::<MultisigMessageMtaTrans>::with_capacity(n)).collect::<Vec<_>>();
        for each in message.iter().cloned(){
            for (index, element) in each.message_list.into_iter().enumerate() {
                redistributed_message[index].push(element);
            }
        }
        let parties: Vec<_> = parties.into_iter().zip(redistributed_message.iter().cloned())
            .map(|(party, msg)| party.receive(msg).unwrap()).collect();
        // for i in 0..n {
        //     for j in 0..n {
        //         assert_eq!(parties[i].share_state.k * sk_list[j] * compute_sk_mask(j, &r_point, &pk_list, &message_sign.as_bytes()),
        //             parties[i].state.mta_share_mu[j] + parties[j].state.mta_share_nu[i]);
        //     }
        // }
        let duration = (now.elapsed().as_micros() as f32) / (1000.0 * (n as f32));
        println!("{:20} {:8.2}", "Phase 6", duration);

        //Phase7
        let now = cpu_time::ProcessTime::now();
        let (message, parties): (Vec<_>, Vec<_>) = parties.into_iter().map(|each| each.send()).unzip();
        let parties: Vec<_> = parties.into_iter().map(|each| each.receive(message.clone()).unwrap()).collect();
        let duration = (now.elapsed().as_micros() as f32) / (1000.0 * (n as f32));
        println!("{:20} {:8.2}", "Phase 7", duration);

        //Phase8
        let now = cpu_time::ProcessTime::now();
        let (message, parties): (Vec<_>, Vec<_>) = parties.into_iter().map(|each| each.send()).unzip();
        let parties: Vec<_> = parties.into_iter().map(|each| each.receive(message.clone()).unwrap()).collect();
        let duration = (now.elapsed().as_micros() as f32) / (1000.0 * (n as f32));
        println!("{:20} {:8.2}", "Phase 8", duration);

        // let msg_hash: FE = ECScalar::from(&HSha256::create_hash_from_slice(&message_sign.as_bytes()));
        // let r_coor: FE = ECScalar::from(&r_point.x_coor().unwrap());

        //Phase9 (aka complete)
        let now = cpu_time::ProcessTime::now();
        let (message, parties): (Vec<_>, Vec<_>) = parties.into_iter().map(|each| each.send()).unzip();
        // for i in 0..n {
        //     let sigma_i = (1..n).fold(parties[i].state.mta_share_mu[0] + parties[i].state.mta_share_nu[0], 
        //         |sum, j| sum + parties[i].state.mta_share_mu[j] + parties[i].state.mta_share_nu[j]
        //     );
        //     assert_eq!(msg_hash, parties[i].share_state.message_hash);
        //     assert_eq!(sigma_i, parties[i].state.sigma_share);
        //     assert_eq!(message[i].s_share, parties[i].share_state.k * msg_hash + sigma_i * r_coor)
        // }
        let _: Vec<_> = parties.into_iter().map(|each| each.receive(message.clone()).unwrap()).collect();
        let duration = (now.elapsed().as_micros() as f32) / (1000.0 * (n as f32));
        println!("{:20} {:8.2}", "Phase 9", duration);
    }

    #[test]
    fn test_multisig_2_parties() {
        run_multisig(2);
    }

    #[test]
    fn test_multisig_4_parties() {
        run_multisig(4);
    }

    #[test]
    fn test_multisig_6_parties() {
        run_multisig(6);
    }

    #[test]
    fn test_multisig_8_parties() {
        run_multisig(8);
    }

}
