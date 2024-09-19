use bi_polynomial::{calculate_points, interpolate_poly_scalar};
use bls12_381_plus::elliptic_curve::hash2curve::ExpandMsgXmd;
use bls12_381_plus::elliptic_curve::Group;
use bls12_381_plus::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use bytes::BytesMut;
use ff::Field;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::ops::Neg;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KzgCrs {
    g1: G1Projective,          // Generator of group G1
    g2: G1Projective,          // Another point generated through HashToCurve
    g1_tau: Vec<G1Projective>, // Powers of g
    g2_tau: Vec<G1Projective>, // Similarly, powers of hat_g
    h: G2Projective,           // Generator of group G2
    h_tau: G2Projective,       // Tau-th power of the generator of group G2
    t: usize,                  // Bivariate asymmetric polynomials degree d1 = t
    f: usize,                  // Bivariate asymmetric polynomials degree d2 = f
    n: usize,                  // Total number of nodes
    sc1: G1Projective,         // Schnorr generator 1
    sc2: G1Projective,         // Schnorr generator 2
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KzgCrsTransmit {
    // An intermediate structure that is more suitable for network transmission of CRS.
    g1: Vec<u8>,     // Generator of group G1
    g2: Vec<u8>,     // Another point generated through HashToCurve
    g1_tau: Vec<u8>, // Powers of g
    g2_tau: Vec<u8>, // Similarly, powers of hat_g
    h: Vec<u8>,      // Generator of group G2
    h_tau: Vec<u8>,  // Tau-th power of the generator of group G2
    t: usize,        // Bivariate asymmetric polynomials degree d1 = t
    f: usize,        // Bivariate asymmetric polynomials degree d2 = f
    n: usize,        // Total number of nodes
    sc1: Vec<u8>,    // Schnorr generator 1
    sc2: Vec<u8>,    // Schnorr generator 2
}

pub struct SchnorrPi {
    u: G1Projective,       // Commitment
    c: Scalar,             // Challenge
    r: Scalar,             // Reply
    pk: Vec<G1Projective>, // A set of public key
}

impl KzgCrs {
    pub fn setup(
        t: usize, // Threshold
        f: usize, // Malicious Node
        n: usize, // Total number of nodes
        // The following four variables will be used as input to calculate the random generator of HashToCurve.
        msg_zk: &str,
        dst_zk: &str,
        msg_sc: &str,
        dst_sc: &str,
    ) -> Self {
        let mut rng = OsRng;
        // Select two generators.
        let g1 = G1Projective::GENERATOR;
        let g2 = G1Projective::hash::<ExpandMsgXmd<Sha256>>(msg_zk.as_ref(), dst_zk.as_ref());
        // Choose a random number tau and start computing the Power-of-Tau.
        let tau: Scalar = Scalar::random(&mut rng);
        let mut g1_tau: Vec<G1Projective> = Vec::with_capacity(t + 1);
        let mut g2_tau: Vec<G1Projective> = Vec::with_capacity(t + 1);
        g1_tau.push(g1 * Scalar::ONE);
        g2_tau.push(g2 * Scalar::ONE);
        for i in 1..=t {
            g1_tau.push(tau * g1_tau[i - 1]);
            g2_tau.push(tau * g2_tau[i - 1]);
        }
        // Select generator.
        let h = G2Projective::GENERATOR;
        let h_tau = h * tau;
        // Calculating CRS for Schnorr Protocol.
        let (sc1, sc2) = (
            G1Projective::GENERATOR,
            G1Projective::hash::<ExpandMsgXmd<Sha256>>(msg_sc.as_ref(), dst_sc.as_ref()),
        );
        KzgCrs {
            g1,
            g2,
            g1_tau,
            g2_tau,
            h,
            h_tau,
            t,
            f,
            n,
            sc1,
            sc2,
        }
    }

    pub fn convert2serializable(&self) -> KzgCrsTransmit {
        // Convert to a structure suitable for network transmission.
        let mut g1: Vec<u8> = Vec::with_capacity(96);
        g1.extend(self.g1.to_uncompressed());
        let mut g2: Vec<u8> = Vec::with_capacity(96);
        g2.extend(self.g2.to_uncompressed());
        let mut g1_tau: Vec<u8> = Vec::with_capacity(self.g1_tau.len() * 96);
        let mut g2_tau: Vec<u8> = Vec::with_capacity(self.g2_tau.len() * 96);
        for i in 0..self.g1_tau.len() {
            g1_tau.extend(self.g1_tau[i].to_uncompressed());
            g2_tau.extend(self.g2_tau[i].to_uncompressed());
        }
        let mut h: Vec<u8> = Vec::with_capacity(192);
        h.extend(self.h.to_uncompressed());
        let mut h_tau: Vec<u8> = Vec::with_capacity(192);
        h_tau.extend(self.h_tau.to_uncompressed());
        let mut sc1: Vec<u8> = Vec::with_capacity(96);
        sc1.extend(self.sc1.to_uncompressed());
        let mut sc2: Vec<u8> = Vec::with_capacity(96);
        sc2.extend(self.sc2.to_uncompressed());
        KzgCrsTransmit {
            g1,
            g2,
            g1_tau,
            g2_tau,
            h,
            h_tau,
            t: self.t,
            f: self.f,
            n: self.n,
            sc1,
            sc2,
        }
    }

    pub fn convert2deserializable(kzg_crs_transmit: KzgCrsTransmit) -> KzgCrs {
        // Convert data suitable for network transmission structure into CRS for calculation
        let g1: G1Projective =
            G1Projective::from_uncompressed(&kzg_crs_transmit.g1.try_into().unwrap()).unwrap();
        let g2: G1Projective =
            G1Projective::from_uncompressed(&kzg_crs_transmit.g2.try_into().unwrap()).unwrap();
        let len = kzg_crs_transmit.g1_tau.len() / 96;
        let mut g1_tau: Vec<G1Projective> = Vec::with_capacity(len);
        let mut g2_tau: Vec<G1Projective> = Vec::with_capacity(len);
        for i in 0..len {
            g1_tau.push(
                G1Projective::from_uncompressed(
                    (&kzg_crs_transmit.g1_tau[i * 96..i * 96 + 96])
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            );
            g2_tau.push(
                G1Projective::from_uncompressed(
                    (&kzg_crs_transmit.g2_tau[i * 96..i * 96 + 96])
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            );
        }
        let h: G2Projective =
            G2Projective::from_uncompressed(&kzg_crs_transmit.h.try_into().unwrap()).unwrap();
        let h_tau: G2Projective =
            G2Projective::from_uncompressed(&kzg_crs_transmit.h_tau.try_into().unwrap()).unwrap();
        let sc1: G1Projective =
            G1Projective::from_uncompressed(&kzg_crs_transmit.sc1.try_into().unwrap()).unwrap();
        let sc2: G1Projective =
            G1Projective::from_uncompressed(&kzg_crs_transmit.sc2.try_into().unwrap()).unwrap();
        KzgCrs {
            g1,
            g2,
            g1_tau,
            g2_tau,
            h,
            h_tau,
            t: kzg_crs_transmit.t,
            f: kzg_crs_transmit.f,
            n: kzg_crs_transmit.n,
            sc1,
            sc2,
        }
    }

    pub fn uni_commit(&self, coef: &Vec<Scalar>, hat_coeff: &Vec<Scalar>) -> G1Projective {
        // Compute the commitment of a univariate polynomial.
        let mut commitment: G1Projective = G1Projective::identity();
        let mut hat_commitment: G1Projective = G1Projective::identity();
        for i in 0..coef.len() {
            commitment += coef[i] * self.g1_tau[i];
            hat_commitment += hat_coeff[i] * self.g2_tau[i];
        }
        commitment + hat_commitment
    }

    pub fn bi_commit(
        &self,
        coef: &Vec<Vec<Scalar>>,
        hat_coef: &Vec<Vec<Scalar>>,
    ) -> Vec<G1Projective> {
        // Compute commitments for bivariate asymmetric polynomials.
        let mut commitment: Vec<G1Projective> = Vec::with_capacity(self.f + 1);
        for j in 0..=self.f {
            let mut c: G1Projective = G1Projective::identity();
            let mut hat_c: G1Projective = G1Projective::identity();
            for i in 0..=self.t {
                // Calculate the corresponding commitment for each column.
                c += coef[j][i] * self.g1_tau[i];
                hat_c += hat_coef[j][i] * self.g2_tau[i];
            }
            commitment.push(c + hat_c);
        }
        commitment
    }

    pub fn divide_com(
        &self,
        com: &Vec<G1Projective>,
        vander_matrix: &Vec<Vec<Scalar>>,
    ) -> Vec<G1Projective> {
        // Split the commitment computed by bi_commit into n final commitments.
        let mut cm: Vec<G1Projective> = Vec::with_capacity(self.n + 1);
        cm.push(self.g1 + self.g2);
        for i in 1..=self.n {
            let vander = &vander_matrix[i];
            let mut temp_com: G1Projective = G1Projective::identity();
            for y in 0..=self.f {
                temp_com += com[y] * vander[y];
            }
            cm.push(temp_com);
        }
        cm
    }

    pub fn eval(
        &self,
        coef: &Vec<Scalar>,
        hat_coef: &Vec<Scalar>,
        vander_matrix: &Vec<Vec<Scalar>>,
        x: usize,
    ) -> (Scalar, Scalar, G1Affine) {
        // Compute the value of the polynomial at x and its proof.
        let d = coef.len() - 1;
        let n = vander_matrix.len() - 1;
        let mut p_set: Vec<Scalar> = Vec::with_capacity(n + 1);
        let mut hat_p_set: Vec<Scalar> = Vec::with_capacity(n + 1);
        p_set.push(Scalar::ZERO);
        hat_p_set.push(Scalar::ZERO);
        for index in 1..=n {
            p_set.push(calculate_points(&coef, &vander_matrix[index]));
            hat_p_set.push(calculate_points(&hat_coef, &vander_matrix[index]));
        }
        // In order to calculate the proof of a certain point, the parameter Tau is needed in the calculation, but this random number is not public.
        // Please refer to the paper for the detailed principles of the following steps.
        // We construct a special polynomial through interpolation and use uni_commit to commit.
        // Finally, the proof of this point is calculated.
        let (points, hat_points) =
            Self::points_excepted_id(&p_set, &hat_p_set, &p_set[x], &hat_p_set[x], x, n, d);
        let pi = G1Affine::from(self.uni_commit(
            &interpolate_poly_scalar(&points),
            &interpolate_poly_scalar(&hat_points),
        ));
        (p_set[x], hat_p_set[x], pi)
    }

    pub fn multi_eval(
        &self,
        coef: &Vec<Scalar>,
        hat_coef: &Vec<Scalar>,
        vander_matrix: &Vec<Vec<Scalar>>,
    ) -> (Vec<Scalar>, Vec<Scalar>, Vec<G1Affine>) {
        // Batch computation of point sets and proof sets.
        let d = coef.len() - 1;
        let n = vander_matrix.len() - 1;
        let mut p_set: Vec<Scalar> = Vec::with_capacity(n + 1);
        let mut hat_p_set: Vec<Scalar> = Vec::with_capacity(n + 1);
        p_set.push(Scalar::ZERO);
        hat_p_set.push(Scalar::ZERO);
        for index in 1..=n {
            p_set.push(calculate_points(&coef, &vander_matrix[index]));
            hat_p_set.push(calculate_points(&hat_coef, &vander_matrix[index]));
        }
        let mut pi: Vec<G1Affine> = Vec::with_capacity(n + 1);
        pi.push(G1Affine::identity());
        // The principle is the same as in Eval.
        for index in 1..=n {
            let (points, hat_points) = Self::points_excepted_id(
                &p_set,
                &hat_p_set,
                &p_set[index],
                &hat_p_set[index],
                index,
                n,
                d,
            );
            let temp_coff = interpolate_poly_scalar(&points);
            let temp_hat_coff = interpolate_poly_scalar(&hat_points);
            pi.push(G1Affine::from(self.uni_commit(&temp_coff, &temp_hat_coff)));
        }
        (p_set, hat_p_set, pi)
    }
    pub fn verify(
        &self,
        cm: &Vec<G1Projective>,
        i: usize,
        j: usize,
        p: &Scalar,
        hat_p: &Scalar,
        pi: &G1Affine,
    ) -> bool {
        // Use bilinear pairing to verify the correctness of the shares.
        let cm_p: G1Affine = G1Affine::from(cm[j] + (p * self.g1).neg() + (hat_p * self.g2).neg());
        let h = G2Affine::from(self.h);
        let h_tau_i = G2Affine::from(self.h_tau - self.h * Scalar::from(i as u64));
        pairing(&cm_p, &h) == pairing(&pi, &h_tau_i)
    }

    pub fn multi_verify(
        &self,
        cm: &Vec<G1Projective>,
        id: usize,
        p: &Vec<Scalar>,
        hat_p: &Vec<Scalar>,
        pi: &Vec<G1Affine>,
    ) -> bool {
        // Verify point sets and proof sets in batches.
        let n = pi.len() - 1;
        let temp_cm = &cm[id];
        let h = G2Affine::from(self.h);
        for index in 1..=n {
            let cm_p: G1Affine = G1Affine::from(
                temp_cm + (p[index] * self.g1).neg() + (hat_p[index] * self.g2).neg(),
            );
            let h_tau_i = G2Affine::from(self.h_tau - self.h * Scalar::from(index as u64));
            if pairing(&cm_p, &h) != pairing(&pi[index], &h_tau_i) {
                return false;
            }
        }
        true
    }

    fn points_excepted_id(
        p_set: &Vec<Scalar>,
        hat_p_set: &Vec<Scalar>,
        p: &Scalar,
        hat_p: &Scalar,
        id: usize,
        n: usize,
        d: usize,
    ) -> (Vec<(Scalar, Scalar)>, Vec<(Scalar, Scalar)>) {
        // Construct a special point set that does not include the share at x=id.
        let index_scalar = Scalar::from(id as u64);
        let mut points: Vec<(Scalar, Scalar)> = Vec::with_capacity(d);
        let mut hat_points: Vec<(Scalar, Scalar)> = Vec::with_capacity(d);
        let mut count = 0usize;
        for i in 1..=n {
            if i != id {
                let i_scalar = Scalar::from(i as u64);
                let denominator = i_scalar - index_scalar;
                points.push((i_scalar, (p_set[i] - p) / denominator));
                hat_points.push((i_scalar, (hat_p_set[i] - hat_p) / denominator));
                count += 1;
                if count == d {
                    break;
                }
            }
        }
        (points, hat_points)
    }

    pub fn schnorr_prove(&self, z: &Vec<Scalar>, hat_z: &Vec<Scalar>) -> (SchnorrPi, SchnorrPi) {
        // Generate non-interactive Schnorr proofs.
        // m is the total number of generated public and private key pairs.
        let m = z.len();
        let mut rng = OsRng;
        let (r1, r2) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let (u1, u2) = (r1 * self.sc1, r2 * self.sc2);
        let (mut pk_z, mut pk_hat_z): (Vec<G1Projective>, Vec<G1Projective>) =
            (Vec::with_capacity(m), Vec::with_capacity(m));
        let (mut sum_z, mut sum_hat_z): (Scalar, Scalar) = (Scalar::ZERO, Scalar::ZERO);
        let (mut bs, mut hat_bs): (BytesMut, BytesMut) = (BytesMut::new(), BytesMut::new());
        bs.extend(self.sc1.to_uncompressed());
        hat_bs.extend(self.sc2.to_uncompressed());
        for index in 0..m {
            // Sum the private key shares.
            sum_z += z[index];
            sum_hat_z += hat_z[index];
            // Compute the corresponding public key share for each private key share.
            pk_z.push(z[index] * self.sc1);
            pk_hat_z.push(hat_z[index] * self.sc2);
            // Concatenate the byte streams in order.
            bs.extend(pk_z[index].to_uncompressed()); //字节流拼接
            hat_bs.extend(pk_hat_z[index].to_uncompressed());
        }
        let c1 = Scalar::hash::<ExpandMsgXmd<Sha256>>(bs.as_ref(), &u1.to_uncompressed());
        let c2 = Scalar::hash::<ExpandMsgXmd<Sha256>>(hat_bs.as_ref(), &u2.to_uncompressed());
        let r1 = r1 + c1 * sum_z;
        let r2 = r2 + c2 * sum_hat_z;
        (
            SchnorrPi {
                u: u1,
                c: c1,
                r: r1,
                pk: pk_z,
            },
            SchnorrPi {
                u: u2,
                c: c2,
                r: r2,
                pk: pk_hat_z,
            },
        )
    }

    pub fn schnorr_verify(&self, pi: &SchnorrPi, hat_pi: &SchnorrPi) -> bool {
        // Verify that the Schnorr protocol proof is valid.
        let (mut bs, mut hat_bs): (BytesMut, BytesMut) = (BytesMut::new(), BytesMut::new());
        bs.extend(self.g1.to_uncompressed());
        hat_bs.extend(self.g2.to_uncompressed());
        let (mut pk, mut hat_pk): (G1Projective, G1Projective) =
            (G1Projective::identity(), G1Projective::identity());
        for index in 0..pi.pk.len() {
            bs.extend(pi.pk[index].to_uncompressed());
            pk += pi.pk[index];
            hat_bs.extend(hat_pi.pk[index].to_uncompressed());
            hat_pk += hat_pi.pk[index];
        }
        let c1 = Scalar::hash::<ExpandMsgXmd<Sha256>>(bs.as_ref(), &pi.u.to_uncompressed());
        let c2 = Scalar::hash::<ExpandMsgXmd<Sha256>>(hat_bs.as_ref(), &hat_pi.u.to_uncompressed());
        c1.eq(&pi.c)
            && c2.eq(&hat_pi.c)
            && (pi.r * self.g1).eq(&(pi.u + pi.c * pk))
            && (hat_pi.r * self.g2).eq(&(hat_pi.u + hat_pi.c * hat_pk))
    }
}
