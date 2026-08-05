use bls12_381_plus::elliptic_curve_013::hash2curve::ExpandMsgXmd;
use bls12_381_plus::{G1Projective, Scalar};
use bytes::BytesMut;
use ff::Field;
use sha2::Sha256;

pub struct SchnorrCrs {
    t: usize,          // Bivariate asymmetric polynomials degree d1 = t
    f: usize,          // Bivariate asymmetric polynomials degree d2 = f
    n: usize,          // Total number of nodes
    sc1: G1Projective, // Schnorr generator 1
}

#[derive(Debug, Clone)]
pub struct SchnorrPi {
    u: G1Projective,      // Commitment
    c: Scalar,            // Challenge
    r: Scalar,            // Reply
    pub pk: G1Projective, // A set of public key
}

impl SchnorrCrs {
    pub fn setup(
        t: usize, // Threshold
        f: usize, // Malicious Node
        n: usize, // Total number of nodes
    ) -> Self {
        let sc1 = G1Projective::GENERATOR;
        SchnorrCrs { t, f, n, sc1 }
    }

    pub fn schnorr_prove(&self, z: &Scalar) -> SchnorrPi {
        // Generate non-interactive Schnorr proofs.
        // m is the total number of generated public and private key pairs.
        let mut rng = rand::rng();
        let r1 = Scalar::random(&mut rng);
        let u1 = r1 * self.sc1;
        let pk_z: G1Projective = z * self.sc1;
        let sum_z: Scalar = z.clone();
        let mut bs: BytesMut = BytesMut::new();
        bs.extend(self.sc1.to_uncompressed());
        // Concatenate the byte streams in order.
        bs.extend(pk_z.to_uncompressed()); //字节流拼接
        let c1 = Scalar::hash::<ExpandMsgXmd<Sha256>>(bs.as_ref(), &u1.to_uncompressed());
        let r1 = r1 + c1 * sum_z;
        SchnorrPi {
            u: u1,
            c: c1,
            r: r1,
            pk: pk_z,
        }
    }

    pub fn schnorr_verify(&self, pi: &SchnorrPi) -> bool {
        // Verify that the Schnorr protocol proof is valid.
        let mut bs: BytesMut = BytesMut::new();
        bs.extend(self.sc1.to_uncompressed());
        let pk: G1Projective = pi.pk.clone();
        bs.extend(pi.pk.to_uncompressed());
        let c1 = Scalar::hash::<ExpandMsgXmd<Sha256>>(bs.as_ref(), &pi.u.to_uncompressed());
        c1.eq(&pi.c) && (pi.r * self.sc1).eq(&(pi.u + pi.c * pk))
    }
}

#[cfg(test)]
mod tests_origin_schnorr {
    use super::*;
    use std::time::Instant;

    const N: usize = 128; // Total number of nodes
    const T: usize = 42; // Reconstruction Threshold
    const F: usize = 42; // Malicious Node
    #[test]
    fn test_schnorr() {
        let mut rng = rand::rng();
        let sc_crs = SchnorrCrs::setup(T, F, N);
        let origin_secret: Scalar = Scalar::random(&mut rng);

        let start = Instant::now();
        let sc_pi = sc_crs.schnorr_prove(&origin_secret);
        let end = start.elapsed();
        println!(
            "schnorr证明生成时间: {:?} us, 证明内存占用 {:?} bytes",
            end.as_micros(),
            size_of_val(&sc_pi)
        );

        let start = Instant::now();
        let ver = sc_crs.schnorr_verify(&sc_pi);
        let end = start.elapsed();
        println!("Schnorr验证结果:{:?}, 时间: {:?}us", ver, end.as_micros());
    }
}
