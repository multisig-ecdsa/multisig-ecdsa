use serde::{Deserialize, Serialize};
use curv_kzen::arithmetic::Modulo;
use curv_kzen::arithmetic::Samplable;
use curv_kzen::arithmetic::BasicOps;
use curv_kzen::arithmetic::Integer;
use curv_kzen::arithmetic::Converter;
use curv_kzen::arithmetic::Zero;
use curv_kzen::cryptographic_primitives::hashing::traits::Hash;
use curv_kzen::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv_kzen::elliptic::curves::traits::ECScalar;
use curv_kzen::BigInt;
use curv_kzen::elliptic::curves::secp256_k1::{FE, GE};
use class_group::BinaryQF;
use class_group::pari_init;
use class_group::primitives::cl_dl_public_setup::next_probable_small_prime;
use class_group::primitives::cl_dl_public_setup::{CLGroup, PK, Ciphertext, ProofError};

const SECURITY_PARAMETER: usize = 112;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClassProofAffine {
    s1:         BinaryQF,
    s2:         BinaryQF,
    s3:         GE,
    d1:         BinaryQF,
    d2:         BinaryQF,
    e1:         BinaryQF,
    e2:         BinaryQF,
    u_beta:     BigInt,
    e_rho:      BigInt,
    e_gamma:    BigInt,
    q1:         BinaryQF,
    q2:         BinaryQF,
    r1:         BinaryQF,
    r2:         BinaryQF,
    p1:         GE,
    r_rho:      BigInt,
    r_gamma:    BigInt,
}

impl ClassProofAffine {
    pub fn prove(
        group:            &CLGroup,
        pk:               &PK,
        add_share:        &BigInt, 
        add_rand:         &BigInt, 
        mul_msg:          &BigInt,
        ciphertext_init:  &Ciphertext,
        bind_base:        &GE,
    ) -> Self {

        unsafe { pari_init(100000000, 2) };
        let exp = (SECURITY_PARAMETER as u32) + 80 + 3; // epsilon_d = 80
        let two_pow_exp = BigInt::pow(&BigInt::from(2), exp);
        let b = &two_pow_exp * &group.stilde * &FE::q();
        let b_minus = BigInt::zero() - &b;

        let c1 = &ciphertext_init.c2;
        let c2 = &ciphertext_init.c1;
        let gamma = mul_msg;
        let beta = add_share;
        let rho = add_rand;


        // ============== Step 1 ==============
        let s_rho = BigInt::sample_range(&b_minus, &b);
        let s_gamma = BigInt::sample_range(&b_minus, &b);
        let sb_fe: FE = FE::new_random();
        let s_beta = sb_fe.to_big_int();

        // s1 = (c1^s_g) * (f^s_b) * (pk^s_rho)
        let c1sg = c1.exp(&s_gamma); // c1^s_g
        let fsb = BinaryQF::expo_f(&FE::q(), &group.delta_q, &s_beta); // f^s_b
        let pksrho = pk.0.exp(&s_rho); // pk^s_rho
        let s1temp = fsb.compose(&pksrho).reduce(); // (f^s_b) * (pk^s_rho)
        let s1 = s1temp.compose(&c1sg).reduce(); // (c1^s_g) * (f^s_b) * (pk^s_rho)

        // s2 = (c2^s_g) * (g_q^s_rho)
        let c2sg = c2.exp(&s_gamma); // c2^s_g
        let gq_sr = group.gq.exp(&s_rho); // g_q^s_rho
        let s2 = gq_sr.compose(&c2sg).reduce(); // (c2^s_g) * (g_q^s_rho)

        let s_gamma_fe: FE = ECScalar::from(&s_gamma);
        let s3 = bind_base * &s_gamma_fe;

        // ============== Step 2 ==============
        // Do sampling
        let fs1 = HSha256::create_hash(&[
            &BigInt::from_bytes(&s1.to_bytes()[..]),
            &BigInt::from_bytes(&s2.to_bytes()[..]),
        ]);
        let c = HSha256::create_hash(&[&fs1]).mod_floor(&FE::q());
   
        // ============== Step 3 ==============
        // Compute u_beta, u_rho, u_gamma, d1, d2, e1, e2, d_rho, e_eho, d_gamma, e_gamma
        let u_beta = BigInt::mod_add(&s_beta, &(c.clone() * beta), &FE::q()); 
        let u_rho = s_rho + c.clone() * rho;
        let u_gamma = s_gamma + c.clone() * gamma;

        let d_rho = u_rho.div_floor(&FE::q());
        let e_rho = u_rho.mod_floor(&FE::q());

        let d_gamma = u_gamma.div_floor(&FE::q());
        let e_gamma = u_gamma.mod_floor(&FE::q());

        let d1 = pk.0.exp(&d_rho);
        let d2 = group.gq.exp(&d_rho);

        let e1 = c1.exp(&d_gamma);
        let e2 = c2.exp(&d_gamma);

        // ============== Step 4 （Prover) ==============
        let fs2 = HSha256::create_hash(&[
            &BigInt::from_bytes(&s1.to_bytes()[..]),
            &BigInt::from_bytes(&s2.to_bytes()[..]),
            &u_beta,
            &e_rho,
            &e_gamma,
        ]);
        let ell_bits = 87;
        let two_pow_ellbits = BigInt::pow(&BigInt::from(2), ell_bits);
        let r = HSha256::create_hash(&[&fs2]).mod_floor(&two_pow_ellbits);
        let l = next_probable_small_prime(&r);

        // ============== Step 5 ==============
        let q_rho = u_rho.div_floor(&l);
        let r_rho = u_rho.mod_floor(&l);

        let q_gamma = u_gamma.div_floor(&l);
        let r_gamma = u_gamma.mod_floor(&l);

        let q1 = pk.0.exp(&q_rho);
        let q2 = group.gq.exp(&q_rho);

        let r1 = c1.exp(&q_gamma);
        let r2 = c2.exp(&q_gamma);

        let q_gamma_fe: FE = ECScalar::from(&q_gamma);
        let p1 = bind_base * &q_gamma_fe;

        // ============== Output ==============
        // Prepare output pk

        // Output the zkPoKAff instance
        ClassProofAffine {
            s1,
            s2,
            s3,
            d1,
            d2,
            e1,
            e2,
            u_beta,
            e_rho,
            e_gamma,
            q1,
            q2,
            r1,
            r2,
            p1,
            r_rho,
            r_gamma,
        }
    }

    pub fn verify(&self, group: &CLGroup, pk: &PK, ciphertext_init:  &Ciphertext, ciphertext_trans: &Ciphertext, bind_base: &GE, bind_point: &GE) -> Result<(), ProofError> {

        // ============== Preparation ==============
        unsafe { pari_init(100000000, 2) };
        let c1 = &ciphertext_init.c2;
        let c2 = &ciphertext_init.c1;
        let c1t = &ciphertext_trans.c2;
        let c2t = &ciphertext_trans.c1;

        let mut flag = true;
        let fs1 = HSha256::create_hash(&[
            &BigInt::from_bytes(&self.s1.to_bytes()[..]),
            &BigInt::from_bytes(&self.s2.to_bytes()[..]),
        ]);
        let c = HSha256::create_hash(&[&fs1]).mod_floor(&FE::q());

        let fs2 = HSha256::create_hash(&[
            &BigInt::from_bytes(&self.s1.to_bytes()[..]),
            &BigInt::from_bytes(&self.s2.to_bytes()[..]),
            &self.u_beta,
            &self.e_rho,
            &self.e_gamma,
        ]);
        let ell_bits = 87;
        let two_pow_ellbits = BigInt::pow(&BigInt::from(2), ell_bits);
        let r = HSha256::create_hash(&[&fs2]).mod_floor(&two_pow_ellbits);
        let l = next_probable_small_prime(&r);

        // ============== Range check ==============
        if &self.u_beta > &FE::q() 
            || &self.u_beta < &BigInt::zero() 
            || &self.e_gamma > &FE::q() 
            || &self.e_gamma < &BigInt::zero() 
            || &self.e_rho > &FE::q() 
            || &self.e_rho < &BigInt::zero()
            || &self.r_gamma > &FE::q() 
            || &self.r_gamma < &BigInt::zero()
            || &self.r_rho > &FE::q() 
            || &self.r_rho < &BigInt::zero()
        {
            flag = false;
        }
        debug_assert!(flag == true, "verification failed");

        // ============== Step 4 (Verifier) ==============
        // (d1 e1^q) * (pk^e_rho) * (f^u_beta) * (c1^e_gamma) = (s1) * (c1t^c)
        let d1e1 = self.d1.compose(&self.e1).reduce();
        let d1e1q = d1e1.exp(&FE::q()); // (d1 e1)^q
        let pkerho = pk.0.clone().exp(&self.e_rho); // pk^e_rho
        let fub = BinaryQF::expo_f(&FE::q(), &group.delta_q, &self.u_beta); // f^u_beta
        let c1eg = c1.exp(&self.e_gamma); // c1^e_gamma
        let c1tc = c1t.exp(&c); // c1t^c
        // LHS
        let firstlhs = d1e1q.compose(&pkerho).reduce();
        let firstlhss = firstlhs.compose(&fub).reduce();
        let firstlhsss = firstlhss.compose(&c1eg).reduce();
        // RHS
        let firstrhs = self.s1.compose(&c1tc).reduce();
        if firstlhsss != firstrhs {
            flag = false;
        }
        debug_assert!(flag == true, "verification failed");

        // (d2 e2^q) * (g_q^e_rho) * (c2^e_gamma) = (s2) * (c2t^c)
        let d2e2 = self.d2.compose(&self.e2).reduce();
        let d2e2q = d2e2.exp(&FE::q()); // (d2 e2)^q
        let gqerho = group.gq.exp(&self.e_rho); // g_q^e_rho
        let c2eg = c2.exp(&self.e_gamma); // c2^e_gamma
        let c2tc = c2t.exp(&c); // c2t^c
        // LHS
        let secondlhs = d2e2q.compose(&gqerho).reduce();
        let secondlhss = secondlhs.compose(&c2eg).reduce();
        // RHS
        let secondrhs = self.s2.compose(&c2tc).reduce();
        if secondlhss != secondrhs {
            flag = false;
        }
        debug_assert!(flag == true, "verification failed");

        let e_gamma_fe: FE = ECScalar::from(&self.e_gamma);
        let c_fe: FE = ECScalar::from(&c);
        if bind_base * &e_gamma_fe != self.s3 + bind_point * &c_fe {
            flag = false;
        }
        debug_assert!(flag == true, "verification failed");

        // ============== Step 6 ==============
        // (q1 r1^l) * (pk^r_rho) * (f^u_beta) * (c1^r_gamma) = (s1) * (c1t^c)
        let q1r1 = self.q1.compose(&self.r1).reduce();
        let q1r1q = q1r1.exp(&l); // (q1 r1)^l
        let pkrrho = pk.0.clone().exp(&self.r_rho); // pk^e_rho
        let fub = BinaryQF::expo_f(&FE::q(), &group.delta_q, &self.u_beta); // f^u_beta
        let c1ug = c1.exp(&self.r_gamma); // c1^r_gamma
        let c1tc = c1t.exp(&c); // c1t^c
        // LHS
        let firstlhs = q1r1q.compose(&pkrrho).reduce();
        let firstlhss = firstlhs.compose(&fub).reduce();
        let firstlhsss = firstlhss.compose(&c1ug).reduce();
        // RHS
        let firstrhs = self.s1.compose(&c1tc).reduce();
        if firstlhsss != firstrhs {
            flag = false;
        }
        debug_assert!(flag == true, "verification failed");

        // (q2 r2^l) * (g_q^r_rho) * (c2^r_gamma) = (s2) * (c2t^c)
        let q2r2 = self.q2.compose(&self.r2).reduce();
        let q2r2q = q2r2.exp(&l); // (q2 r2)^l
        let gqrrho = group.gq.exp(&self.r_rho); // g_q^r_rho
        let c2ug = c2.exp(&self.r_gamma); // c2^r_gamma
        let c2tc = c2t.exp(&c); // c2t^c
        // LHS
        let secondlhs = q2r2q.compose(&gqrrho).reduce();
        let secondlhss = secondlhs.compose(&c2ug).reduce();
        // RHS
        let secondrhs = self.s2.compose(&c2tc).reduce();
        if secondlhss != secondrhs {
            flag = false;
        }
        debug_assert!(flag == true, "verification failed");

        let l_fe: FE = ECScalar::from(&l);
        let r_gamma_fe: FE = ECScalar::from(&self.r_gamma);
        if self.p1 * l_fe + bind_base * &r_gamma_fe != self.s3 + bind_point * &c_fe {
            flag = false;
        }
        debug_assert!(flag == true, "verification failed");


        match flag {
            true => Ok(()),
            false => Err(ProofError),
        }
       }
}

#[cfg(test)]
mod test {
    use super::*;
    use class_group::primitives::cl_dl_public_setup;
    #[test]
    pub fn test_affine_proof() {
            
        let seed = BigInt::from_str_radix(
            "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
        , 10).unwrap();
        let group = CLGroup::new_from_setup(&1600, &seed);
        let (_, pk) = group.keygen();

        let gamma = BigInt::from(1000); // from Zq

        // (beta, rho)
        let beta = BigInt::from(1000); // from Zq
        let rho = BigInt::sample_below(&(&group.stilde * BigInt::from(2).pow(80))); // from [0, S]

        // (k, r)
        let k = BigInt::from(2000); // from Zq
        let r = BigInt::sample_below(&(&group.stilde * BigInt::from(2).pow(80))); // from [0, S]

        // (c1, c2) -> Enc(k)
        // c1 = (f^k) * (pk^r)
        // c2 = (g_q)^r
        let ciphertext_k = cl_dl_public_setup::encrypt_predefined_randomness(&group, &pk, &ECScalar::from(&k), &cl_dl_public_setup::SK{0: r});

        // (C1p, C2p) -> Enc(k * gamma + beta)
        // C1p = (c1^gamma) * (f^beta) * (pk^rho)
        // C2p = (c2^gamma) * (g_q)^rho
        let ciphertext_beta = cl_dl_public_setup::encrypt_predefined_randomness(&group, &pk, &ECScalar::from(&beta), &cl_dl_public_setup::SK{0: rho.clone()});
        let ciphertext_scal = cl_dl_public_setup::eval_scal(&ciphertext_k, &gamma);
        let ciphertext_add = cl_dl_public_setup::eval_sum(&ciphertext_scal, &ciphertext_beta);

        let bind_base = GE::random_point();
        let bind_msg: FE = ECScalar::from(&beta);
        let bind_point = bind_base * bind_msg;

        let now = cpu_time::ProcessTime::now();
        let proof_aff = ClassProofAffine::prove(
            &group,
            &pk,
            &beta,
            &rho,
            &gamma, 
            &ciphertext_k,
            &bind_base
        );
        let duration = (now.elapsed().as_micros() as f32) / 1000.0;
        println!("{:20} {:10.2}ms", "", duration);

        let now = cpu_time::ProcessTime::now();
        assert!(proof_aff.verify(&group, &pk, &ciphertext_k, &ciphertext_add, &bind_base, &bind_point).is_ok());
        let duration = (now.elapsed().as_micros() as f32) / 1000.0;
        println!("{:20} {:10.2}ms", "", duration);
    }
}