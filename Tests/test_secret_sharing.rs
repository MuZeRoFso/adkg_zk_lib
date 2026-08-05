use bi_polynomial::*;
use bls12_381_plus::elliptic_curve::Field;
use bls12_381_plus::{G1Affine, Scalar};
use rand::random_range;
use rand::seq::SliceRandom;
use std::time::Instant;
use zk_tool::*;

const N: usize = 16; // Total number of nodes
const T: usize = 5; // Reconstruction Threshold
const F: usize = 5; // Malicious Node

#[test]
fn test_secret_sharing() {
    let mut origin_secret: Vec<Scalar> = Vec::with_capacity(1);
    let mut rng = rand::rng();
    //origin_secret.push(Scalar::from(10000u64));
    origin_secret.push(Scalar::random(&mut rng));
    // Construct using `gen_polynomial_with_secret` and return a bi-matrix,
    // then use `bi2alpha` to return an alpha matrix.
    let (u_matrix, hat_u_matrix, vander_matrix) =
        gen_polynomial_with_secret(T, F, N, &origin_secret);
    println!("The secret is {:?} (Hex).\n", u_matrix[0][0]);
    let (alpha_matrix, hat_alpha_matrix) = bi2alpha(&u_matrix, &hat_u_matrix, &vander_matrix, N);
    // Initialize KZG commitment CRS
    // "Test1", "Test2", "Test3", and "Test4" are the default test parameters, which can be changed arbitrarily.
    let kzg_crs = KzgCrs::setup(T, F, N, "Test1", "Test2", "Test3", "Test4");
    // Use bi_commit for overall commitment.
    let total_commitment = kzg_crs.bi_commit(&u_matrix, &hat_u_matrix);
    // Simulate a random node receiving data, for example, id=i
    let id: usize = random_range(1..=N);
    println!("Random id is {:?}.\n", id);
    // Obtained the overall commitment, we can use Divide_com to separate them.
    let sep_cm = kzg_crs.divide_com(&total_commitment, &vander_matrix);
    // Obtained alpha i, we then perform verification and confirm that the verification passes.
    let (alpha_id, hat_alpha_id) = (alpha_matrix[id].clone(), hat_alpha_matrix[id].clone());
    let temp_cm = kzg_crs.uni_commit(&alpha_id, &hat_alpha_id);
    assert_eq!(
        temp_cm, sep_cm[id],
        "Error! {:?} is NOT EQUAL to {:?}",
        temp_cm, sep_cm[id]
    );
    println!(
        "alpha_{} and hat_alpha_{} have passed verification.\n",
        id, id
    );

    // A random set of t+1 nodes
    let random_id = random_unique_numbers(N, T + 1);
    println!("Random id are {:?}.\n", random_id);
    let mut accept_points: Vec<(Scalar, Scalar)> = Vec::with_capacity(T + 1);
    // The accept set collects the alpha(0) of these nodes for recovery.
    for i in 0..random_id.len() {
        let x: u64 = random_id[i] as u64;
        accept_points.push((Scalar::from(x), alpha_matrix[random_id[i]][0]));
    }
    let temp_secret = interpolate_poly_scalar(&accept_points);
    assert_eq!(
        origin_secret[0], temp_secret[0],
        "Error!{:?} is NOT EQUAL to {:?}\n",
        origin_secret, temp_secret
    );
    println!("origin_secret={:?}", origin_secret);
    println!("temp_secret={:?}", temp_secret);
    println!("Test Secret Sharing Done.");
}

#[test]
fn test_bi_pcs_batch() {
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
        test_bi_pcs(n, t, f);
        println!("==================================");
    }
}

fn test_bi_pcs(n: usize, t: usize, f: usize) {
    let mut origin_secret: Vec<Scalar> = Vec::with_capacity(1);
    let mut rng = rand::rng();
    //origin_secret.push(Scalar::from(10000u64));
    origin_secret.push(Scalar::random(&mut rng));
    // Construct using `gen_polynomial_with_secret` and return a bi-matrix,
    // then use `bi2alpha` to return an alpha matrix.
    let (u_matrix, hat_u_matrix, vander_matrix) =
        gen_polynomial_with_secret(t, f, n, &origin_secret);
    let (alpha_matrix, hat_alpha_matrix) = bi2alpha(&u_matrix, &hat_u_matrix, &vander_matrix, N);
    // Initialize KZG commitment CRS
    let kzg_crs = KzgCrs::setup(t, f, n, "Test1", "Test2", "Test1", "Test2");

    // Use bi_commit for overall commitment.
    let start = Instant::now();
    let total_commitment = kzg_crs.bi_commit(&u_matrix, &hat_u_matrix);
    let end = start.elapsed();
    println!("承诺生成耗时: {} us", end.as_micros());

    let sep_cm = kzg_crs.divide_com(&total_commitment, &vander_matrix);

    let (alpha_id, hat_alpha_id) = (alpha_matrix[1].clone(), hat_alpha_matrix[1].clone());

    let start = Instant::now();
    let (point, hat_point, proof) = kzg_crs.eval(&alpha_id, &hat_alpha_id, &vander_matrix, 1);
    let end = start.elapsed();
    println!(
        "单点证明内存占用: {} bytes，单点证明生成耗时: {} us",
        proof.to_compressed().len(),
        end.as_micros()
    );

    let start = Instant::now();
    let ver = kzg_crs.verify(&sep_cm, 1, 1, &point, &hat_point, &proof);
    let end = start.elapsed();
    println!(
        "证明验证结果: {}，证明验证耗时: {} us",
        ver,
        end.as_micros()
    );

    let start = Instant::now();
    let (points, hat_points, proofs) = kzg_crs.multi_eval(&alpha_id, &hat_alpha_id, &vander_matrix);
    let end = start.elapsed();
    println!(
        "批量证明内存占用:{} bytes, 批量证明生成耗时: {} us",
        size_of_val(&proofs) + proofs.len() * G1Affine::COMPRESSED_BYTES,
        end.as_micros()
    );

    let start = Instant::now();
    let ver = kzg_crs.multi_verify(&sep_cm, 1, &points, &hat_points, &proofs);
    let end = start.elapsed();
    println!(
        "证明验证结果: {}，证明验证耗时: {} us",
        ver,
        end.as_micros()
    );
}

fn random_unique_numbers(n: usize, count: usize) -> Vec<usize> {
    // Randomly generate count of IDs
    let mut numbers: Vec<usize> = (1..=n).collect();
    let mut rng = rand::rng();
    numbers.shuffle(&mut rng);
    numbers.truncate(count);
    numbers
}
