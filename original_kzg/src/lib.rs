use bi_polynomial::*;
use bls12_381_plus::elliptic_curve::Field;
use bls12_381_plus::group::Group;
use bls12_381_plus::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar, pairing};
use std::ops::Neg;

pub struct KzgCrs {
    g1: G1Projective,          // Generator of group G1
    g1_tau: Vec<G1Projective>, // Powers of g
    h: G2Projective,           // Generator of group G2
    h_tau: G2Projective,       // Tau-th power of the generator of group G2
    t: usize,                  // Bivariate asymmetric polynomials degree d1 = t
    f: usize,                  // Bivariate asymmetric polynomials degree d2 = f
    n: usize,                  // Total number of nodes
}

impl KzgCrs {
    pub fn setup(
        t: usize, // Threshold
        f: usize, // Malicious Node
        n: usize, // Total number of nodes
    ) -> Self {
        let mut rng = rand::rng();
        let g1 = G1Projective::GENERATOR;
        // Choose a random number tau and start computing the Power-of-Tau.
        let tau: Scalar = Scalar::random(&mut rng);
        let mut g1_tau: Vec<G1Projective> = Vec::with_capacity(t + 1);
        g1_tau.push(g1 * Scalar::ONE);
        for i in 1..=t {
            g1_tau.push(tau * g1_tau[i - 1]);
        }
        // Select generator.
        let h = G2Projective::GENERATOR;
        let h_tau = h * tau;
        // Calculating CRS for Schnorr Protocol.
        KzgCrs {
            g1,
            g1_tau,
            h,
            h_tau,
            t,
            f,
            n,
        }
    }

    pub fn uni_commit(&self, coef: &Vec<Scalar>) -> G1Projective {
        // Compute the commitment of a univariate polynomial.
        let mut commitment: G1Projective = G1Projective::identity();
        for i in 0..coef.len() {
            commitment += coef[i] * self.g1_tau[i];
        }
        commitment
    }

    pub fn eval(
        &self,
        coef: &Vec<Scalar>,
        vander_matrix: &Vec<Vec<Scalar>>,
        x: usize,
    ) -> (Scalar, G1Affine) {
        // Compute the value of the polynomial at x and its proof.
        let d = coef.len() - 1;
        let n = vander_matrix.len() - 1;
        let mut p_set: Vec<Scalar> = Vec::with_capacity(n + 1);
        p_set.push(Scalar::ZERO);
        for index in 1..=n {
            p_set.push(calculate_point(&coef, &vander_matrix[index]));
        }
        let points = Self::points_excepted_id(&p_set, &p_set[x], x, n, d);
        let pi = G1Affine::from(self.uni_commit(&interpolate_poly_scalar(&points)));
        (p_set[x], pi)
    }

    pub fn multi_eval(
        &self,
        coef: &Vec<Scalar>,
        vander_matrix: &Vec<Vec<Scalar>>,
    ) -> (Vec<Scalar>, Vec<G1Affine>) {
        // Batch computation of point sets and proof sets.
        let d = coef.len() - 1;
        let n = vander_matrix.len() - 1;
        let mut p_set: Vec<Scalar> = Vec::with_capacity(n + 1);
        p_set.push(Scalar::ZERO);
        for index in 1..=n {
            p_set.push(calculate_point(&coef, &vander_matrix[index]));
        }
        let mut pi_set: Vec<G1Affine> = Vec::with_capacity(n + 1);
        pi_set.push(G1Affine::identity());
        // The principle is the same as in Eval.
        for index in 1..=n {
            let points = Self::points_excepted_id(&p_set, &p_set[index], index, n, d);
            let temp_coff = interpolate_poly_scalar(&points);
            pi_set.push(G1Affine::from(self.uni_commit(&temp_coff)));
        }
        (p_set, pi_set)
    }

    pub fn verify(&self, cm: &G1Projective, i: usize, p: &Scalar, pi: &G1Affine) -> bool {
        let cm_p: G1Affine = G1Affine::from(cm + (p * self.g1).neg());
        let h = G2Affine::from(self.h);
        let h_tau_i = G2Affine::from(self.h_tau - self.h * Scalar::from(i as u64));
        pairing(&cm_p, &h) == pairing(&pi, &h_tau_i)
    }

    pub fn multi_verify(&self, cm: &G1Projective, p: &Vec<Scalar>, pi: &Vec<G1Affine>) -> bool {
        // Verify point sets and proof sets in batches.
        let n = pi.len() - 1;
        let h = G2Affine::from(self.h);
        for index in 1..=n {
            let cm_p: G1Affine = G1Affine::from(cm + (p[index] * self.g1).neg());
            let h_tau_i = G2Affine::from(self.h_tau - self.h * Scalar::from(index as u64));
            if pairing(&cm_p, &h) != pairing(&pi[index], &h_tau_i) {
                return false;
            }
        }
        true
    }

    fn points_excepted_id(
        p_set: &Vec<Scalar>,
        p: &Scalar,
        id: usize,
        n: usize,
        d: usize,
    ) -> Vec<(Scalar, Scalar)> {
        // Construct a special point set that does not include the share at x=id.
        let index_scalar = Scalar::from(id as u64);
        let mut points: Vec<(Scalar, Scalar)> = Vec::with_capacity(d);
        let mut count = 0usize;
        for i in 1..=n {
            if i != id {
                let i_scalar = Scalar::from(i as u64);
                let denominator = i_scalar - index_scalar;
                points.push((i_scalar, (p_set[i] - p) / denominator));
                count += 1;
                if count == d {
                    break;
                }
            }
        }
        points
    }
}

#[cfg(test)]
mod tests_original_kzg {
    use crate::KzgCrs;
    use bls12_381_plus::elliptic_curve::Field;
    use bls12_381_plus::{G1Affine, Scalar};
    use std::mem::size_of_val;
    use std::time::Instant;
    use bls12_381_plus::group::GroupEncoding;

    #[test]
    fn test_uni_kzg_batch() {
        let ntf_batch: Vec<(usize, usize, usize)> = vec![
            (16, 5, 5),
            (16, 10, 5),
            (32, 10, 10),
            (32, 20, 10),
            (64, 21, 21),
            (64, 42, 21),
            (128, 42, 42),
            (128, 84, 42),
        ];
        for (n, t, f) in ntf_batch {
            println!("==================================");
            println!("n:{},t:{},f:{}", n, t, f);
            test_uni_kzg(n, t, f);
            println!("==================================");
        }
    }

    fn test_uni_kzg(n: usize, t: usize, f: usize) {
        let mut rng = rand::rng();
        let origin_secret: Scalar = Scalar::random(&mut rng);
        let mut u: Vec<Scalar> = Vec::with_capacity(t + 1);
        u.push(origin_secret);
        for _ in 1..=t {
            u.push(Scalar::random(&mut rng));
        }
        let vander = init_vandermonde(t, n);

        let kzg_crs = KzgCrs::setup(t, f, n);
        let start = Instant::now();
        let commitment = kzg_crs.uni_commit(&u);
        let end = start.elapsed();
        println!("承诺生成耗时: {} us", end.as_micros());

        let start = Instant::now();
        let (point, proof) = kzg_crs.eval(&u, &vander, 1);
        let end = start.elapsed();
        println!(
            "单点证明内存占用: {} bytes，单点证明生成耗时: {} us",
            proof.to_compressed().len(),
            end.as_micros()
        );


        let start = Instant::now();
        let ver = kzg_crs.verify(&commitment, 1, &point, &proof);
        let end = start.elapsed();
        println!(
            "证明验证结果: {}，证明验证耗时: {} us",
            ver,
            end.as_micros()
        );

        let start = Instant::now();
        let (points, proofs) = kzg_crs.multi_eval(&u, &vander);
        let end = start.elapsed();
        println!(
            "批量证明内存占用:{} bytes, 批量证明生成耗时: {} us",
            size_of_val(&proofs) + proofs.len() * G1Affine::COMPRESSED_BYTES,
            end.as_micros()
        );

        let start = Instant::now();
        let ver = kzg_crs.multi_verify(&commitment, &points, &proofs);
        let end = start.elapsed();
        println!(
            "证明验证结果: {}，证明验证耗时: {} us",
            ver,
            end.as_micros()
        );
    }

    fn init_vandermonde(t: usize, n: usize) -> Vec<Vec<Scalar>> {
        // Generates the (t+1) * n vandermonde matrix
        let mut vander_matrix: Vec<Vec<Scalar>> = Vec::with_capacity(n + 1);
        vander_matrix.push(vec![Scalar::ONE; t + 1]);
        for i in 1..=n {
            let mut temp_row: Vec<Scalar> = Vec::with_capacity(t + 1);
            // The first element is always 1
            temp_row.push(Scalar::from(1u64));
            for j in 1..=t {
                temp_row.push(temp_row[j - 1] * Scalar::from(i as u64));
            }
            vander_matrix.push(temp_row);
        }
        vander_matrix
    }
}
