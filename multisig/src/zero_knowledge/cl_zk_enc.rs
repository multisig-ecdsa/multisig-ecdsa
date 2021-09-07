use serde::{Deserialize, Serialize};
use curv_kzen::arithmetic::One;
use curv_kzen::arithmetic::Modulo;
use curv_kzen::arithmetic::Samplable;
use curv_kzen::arithmetic::BasicOps;
use curv_kzen::arithmetic::Integer;
use curv_kzen::arithmetic::Converter;
use curv_kzen::arithmetic::Zero;
use curv_kzen::cryptographic_primitives::hashing::traits::Hash;
use curv_kzen::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv_kzen::elliptic::curves::traits::{ECPoint, ECScalar};
use curv_kzen::BigInt;
use curv_kzen::elliptic::curves::secp256_k1::{FE, GE};
use class_group::BinaryQF;
use class_group::pari_init;
use class_group::primitives::cl_dl_public_setup::next_probable_small_prime;
use class_group::primitives::cl_dl_public_setup::{CLGroup, SK, PK, Ciphertext, ProofError};

const SECURITY_PARAMETER: usize = 112;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClassProofEncrypt {
    s1: BinaryQF,
    s2: BinaryQF,
    s3: BinaryQF,
    s_hat: GE,
    d1: BinaryQF,
    d2: BinaryQF,
    d3: BinaryQF,
    u_m: BigInt,
    e_rho: BigInt,
    e_k: BigInt,
    q1: BinaryQF,
    q2: BinaryQF,
    q3: BinaryQF,
    r_rho: BigInt,
    r_k: BigInt,
}

impl ClassProofEncrypt{
    pub fn prove(
        group:      &CLGroup,
        pk:         &PK,
        sk:         &SK,
        msg:        &BigInt, 
        rand:       &BigInt, 
        bind_base:  &GE,
    ) -> Self {

        unsafe { pari_init(10000000, 2) };
        let exp = (SECURITY_PARAMETER as u32) + 80 + 3; // epsilon_d = 80
        let two_pow_exp = BigInt::pow(&BigInt::from(2), exp);
        let b = &two_pow_exp * &group.stilde * &FE::q();
        let b_minus = BigInt::zero() - &b;
        let m = msg;
        let rho = rand;

        // let rho = BigInt::sample_below(&(&hsmcl.pk.stilde * BigInt::from(2).pow(40))); //according to line 140, the same sampling with sk
        let s_rho = BigInt::sample_range(&b_minus, &b);
        let s_k = BigInt::sample_range(&b_minus, &b);

        //sample s_m, to check
        let sm_fe: FE = FE::new_random();
        let s_m = sm_fe.to_big_int(); //according to line 519

        // calculate commit
        let fsm = BinaryQF::expo_f(&FE::q(), &group.delta_q, &s_m); //f^s_m
        // let c2sk = c2.exp(&s_k);  // c2^s_k
        // let s1 = fsm.compose(&c2sk).reduce();
        let pksrho = pk.0.clone().exp(&s_rho); // pk^s_rho
        let s1 = fsm.compose(&pksrho).reduce();
        let s2 = group.gq.exp(&s_rho); // seems no need to reduce for exp
        let s3 = group.gq.exp(&s_k);
        let s_hat = bind_base * &sm_fe; //s_hat = P_hat^s_m

        //use fiat shamir transform to calculate challenge c
        let fs1 = HSha256::create_hash(&[
            &BigInt::from_bytes(&s1.to_bytes()[..]),
            &BigInt::from_bytes(&s2.to_bytes()[..]),
            &BigInt::from_bytes(&s3.to_bytes()[..]),
            &s_hat.bytes_compressed_to_big_int(),
        ]);
        let c = HSha256::create_hash(&[&fs1]).mod_floor(&FE::q());

        let u_rho = s_rho + &c * rho;
        let u_k = s_k + &c * &sk.0;
        // let u_k = BigInt::mod_add(&s_k, &(&c * &hsmcl.sk), &FE::q());
        // let s_m = sm_fe.to_big_int(); //according to line 519
        let u_m = BigInt::mod_add(&s_m, &(&c * m), &FE::q()); // seems FE::q() is the order, how to make sure = q?

        let d_rho = u_rho.div_floor(&FE::q());
        let d_k = u_k.div_floor(&FE::q());
        let e_rho = u_rho.mod_floor(&FE::q());
        let e_k = u_k.mod_floor(&FE::q());

        // let d1 = c2.exp(&d_k);
        let d1 = pk.0.clone().exp(&d_rho); // d1 = pk^d_rho
        let d2 = group.gq.exp(&d_rho);
        let d3 = group.gq.exp(&d_k);

        //use fiat shamir transform to calculate l
        let fs2 = HSha256::create_hash(&[
            &BigInt::from_bytes(&d1.to_bytes()[..]),
            &BigInt::from_bytes(&d2.to_bytes()[..]),
            &BigInt::from_bytes(&d3.to_bytes()[..]),
            &u_m,
            &e_rho,
            &e_k,
        ]);

        // reconstruct prime l <- Primes(87), 
        // For our case, we need to ensure that we have 2^80 primes 
        // in the challenge set. In order to generate enough prime, 
        // we need to find X such that "80 = X - log_2 X”. 
        // Then X is the number of bits outputted by the Primes() function.
        // X \in (86, 87), so we adopt 87

        let ell_bits = 87; 
        let two_pow_ellbits = BigInt::pow(&BigInt::from(2),ell_bits);
        let r = HSha256::create_hash(&[&fs2]).mod_floor(&two_pow_ellbits);
        let l = next_probable_small_prime(&r);
        // println!("verifier side's SHA256 mod 2^87: {}",r);
        // println!("verifier side's prime l: {}",l);

        let q_rho = u_rho.div_floor(&l);
        let q_k = u_k.div_floor(&l);
        let r_rho = u_rho.mod_floor(&l);
        let r_k = u_k.mod_floor(&l);

        // let q1 = c2.exp(&q_k);
        let q1 = pk.0.exp(&q_rho); // q1 = pk^q_rho
        let q2 = group.gq.exp(&q_rho);
        let q3 = group.gq.exp(&q_k);

        ClassProofEncrypt {
            s1,
            s2,
            s3,
            s_hat,
            d1,
            d2,
            d3,
            u_m,
            e_rho,
            e_k,
            q1,
            q2,
            q3,
            r_rho,
            r_k,
            // c,
        }
    }

    pub fn verify(
        &self,
        group:      &CLGroup,
        pk:         &PK,
        c:          &Ciphertext,
        bind_base:  &GE,
        bind_point: &GE, 
    ) -> Result<(), ProofError>{
        // println!("zkpokenc_cl_dl_lcm executed");
        unsafe { pari_init(100000000, 2) };
        let c1 = &c.c2;
        let c2 = &c.c1;
        let mut flag = true;
        // if HSMCL::setup_verify(&self.pk, &self.seed).is_err() {
        //     flag = false;
        // }

        // use fiat shamir transform to calculate challenge c
        let fs1 = HSha256::create_hash(&[
            &BigInt::from_bytes(&self.s1.to_bytes()[..]),
            &BigInt::from_bytes(&self.s2.to_bytes()[..]),
            &BigInt::from_bytes(&self.s3.to_bytes()[..]),
            &self.s_hat.bytes_compressed_to_big_int(),
        ]);
        let c = HSha256::create_hash(&[&fs1]).mod_floor(&FE::q());
        // let c = self.c.clone();

        // VERIFY STEP 4
        // range check for u_m, e_rhp, e_k
        if &self.u_m > &FE::q() 
            || &self.u_m < &BigInt::zero() 
            || &self.e_rho > &&FE::q()   
            || &self.e_rho < &BigInt::zero()
            || &self.e_k > &&FE::q()  
            || &self.e_k < &BigInt::zero() 
        {
            flag = false;
        }

        // first condition
        let um_fe: FE = ECScalar::from(&self.u_m);
        let phatum = bind_base * &um_fe; //P_hat^u_m, GE::generator() is P_hat
        let c_bias_fe: FE = ECScalar::from(&(c.clone() + BigInt::one()));
        let shatchatc = (self.s_hat + bind_point * &c_bias_fe).sub_point(&bind_point.get_element());
        if shatchatc != phatum {
            flag = false;
        }
        debug_assert!(flag == true, "verification failed");

        // // second condition, c2 version
        // let fum = BinaryQF::expo_f(&FE::q(), &group.delta_q, &self.u_m);
        // let c2ek = c2.exp(&self.e_k);
        // let c2ekfum = fum.compose(&c2ek).reduce();
        // let d1q = self.d1.exp(&FE::q());
        // let d1qc2ekfum = c2ekfum.compose(&d1q).reduce();
        // let c1c = c1.exp(&c);
        // let s1c1c = c1c.compose(&self.s1).reduce();
        // if d1qc2ekfum != s1c1c {
        //     flag = false;
        // }
        // assert!(flag == true, "verification failed");

        // second condition: c2^ek -> pk^erho
        let fum = BinaryQF::expo_f(&FE::q(), &group.delta_q, &self.u_m);
        let pkerho = pk.0.clone().exp(&self.e_rho);
        let pkerhofum = fum.compose(&pkerho).reduce();
        let d1q = self.d1.exp(&FE::q());
        let d1qpkerhofum = pkerhofum.compose(&d1q).reduce();
        let c1c = c1.exp(&c);
        let s1c1c = c1c.compose(&self.s1).reduce();
        if d1qpkerhofum != s1c1c {
            flag = false;
        }
        debug_assert!(flag == true, "verification failed");

        // third condition
        let gqerho = group.gq.exp(&self.e_rho);
        let d2q = self.d2.exp(&FE::q());
        let d2qgqerho = d2q.compose(&gqerho).reduce();
        let c2c = c2.exp(&c);
        let s2c2c = c2c.compose(&self.s2).reduce();
        if d2qgqerho != s2c2c {
            flag = false;
        }
        debug_assert!(flag == true, "verification failed");

        // forth condition
        let gqek = group.gq.exp(&self.e_k);
        let d3q = self.d3.exp(&FE::q());
        let d3qgqek = d3q.compose(&gqek).reduce();
        let pkc = pk.0.exp(&c);
        let s3pkc = pkc.compose(&self.s3).reduce();
        if d3qgqek != s3pkc {
            flag = false;
        }
        debug_assert!(flag == true, "verification failed");

        //use fiat shamir transform

        let fs2 = HSha256::create_hash(&[
            &BigInt::from_bytes(&self.d1.to_bytes()[..]),
            &BigInt::from_bytes(&self.d2.to_bytes()[..]),
            &BigInt::from_bytes(&self.d3.to_bytes()[..]),
            &self.u_m,
            &self.e_rho,
            &self.e_k,
        ]);

        // reconstruct prime l <- Primes(87), 
        // For our case, we need to ensure that we have 2^80 primes 
        // in the challenge set. In order to generate enough prime, 
        // we need to find X such that "80 = X - log_2 X”. 
        // Then X is the number of bits outputted by the Primes() function.
        // X \in (86, 87), so we adopt 87

        let ell_bits = 87;
        let two_pow_ellbits = BigInt::pow(&BigInt::from(2),ell_bits);
        let r = HSha256::create_hash(&[&fs2]).mod_floor(&two_pow_ellbits);
        let l = next_probable_small_prime(&r);
        // println!("verifier side's SHA256 mod 2^87: {}",r);
        // println!("verifier side's prime l: {}",l);

        //VERIFY STEP 6
        // check whether r_rho, r_k is in [0, l-1]
        if self.r_rho < BigInt::zero() 
            || self.r_rho > l 
            || self.r_k < BigInt::zero() 
            || self.r_k > l
        {
            flag = false;
        }
        debug_assert!(flag == true, "verification failed");

        // // first condition: c2 version
        // let c2rk = c2.exp(&self.r_k);
        // let c2rkfum = fum.compose(&c2rk).reduce();
        // let q1l = self.q1.exp(&l);
        // let q1lc2rkfum = c2rkfum.compose(&q1l).reduce();
        // if q1lc2rkfum != s1c1c {
        //     flag = false;
        // }
        // assert!(flag == true, "verification failed");

        // first condition: pk version
        let pkrrho = pk.0.exp(&self.r_rho);
        let pkrrhofum = fum.compose(&pkrrho).reduce();
        let q1l = self.q1.exp(&l);
        let q1lpkrrhofum = pkrrhofum.compose(&q1l).reduce();
        if q1lpkrrhofum != s1c1c {
            flag = false;
        }
        debug_assert!(flag == true, "verification failed");

        // second condition
        let gqrrho = group.gq.exp(&self.r_rho);
        let q2l = self.q2.exp(&l);
        let q2lgqrrho = q2l.compose(&gqrrho).reduce();
        if q2lgqrrho != s2c2c {
            flag = false;
        }
        debug_assert!(flag == true, "verification failed");

        // third condition
        let gqrk = group.gq.exp(&self.r_k);
        let q3l = self.q3.exp(&l);
        let q3lgqrk = q3l.compose(&gqrk).reduce();
        if q3lgqrk != s3pkc {
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
    pub fn test_encrypt_proof() {
            
        let seed = BigInt::from_str_radix(
            "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"
        , 10).unwrap();
        let group = CLGroup::new_from_setup(&1600, &seed);
        let (sk, pk) = group.keygen();

        // (m, rho)
        let msg = BigInt::from(1000); // from Zq
        let rho = BigInt::sample_below(&(&group.stilde * BigInt::from(2).pow(80))); // from [0, S]
        let ciphertext = cl_dl_public_setup::encrypt_predefined_randomness(&group, &pk, &ECScalar::from(&msg), &SK{0: rho.clone()});

        let bind_base = GE::random_point();
        let bind_val: FE = ECScalar::from(&msg);
        let bind_point: GE = bind_base * bind_val;

        let proof = ClassProofEncrypt::prove(
            &group,
            &pk,
            &sk,
            &msg,
            &rho,
            &bind_base,
        );

        assert!(proof.verify(&group, &pk, &ciphertext, &bind_base, &bind_point).is_ok());
    }
}