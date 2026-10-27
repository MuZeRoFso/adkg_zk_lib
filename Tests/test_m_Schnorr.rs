use bls12_381_plus::elliptic_curve::Field;
use bls12_381_plus::{G1Projective, Scalar};
use std::time::{Duration, Instant};
use zk_tool::*;

#[test]
fn test_pk_generate() {
    let (n, t, f, m): (usize, usize, usize, usize) = (16, 5, 5, 2);
    let mut rng = rand::rng();
    // Initialize Schnorr's CRS
    let sc_crs = KzgCrs::setup(t, f, n, "Test1", "Test2", "Test3", "Test4");
    // Randomly select a set of z and hat_z
    let mut origin_secret: Vec<Scalar> = Vec::with_capacity(m);
    let mut hat_secret: Vec<Scalar> = Vec::with_capacity(m);
    for _ in 0..m {
        origin_secret.push(Scalar::random(&mut rng));
        hat_secret.push(Scalar::random(&mut rng));
    }
    println!("The secrets are {:?} (Hex).", origin_secret);
    println!("The hats are {:?} (Hex).", hat_secret);
    // Generate Schnorr proofs for z and hat_z
    let (sc_pi, hat_sc_pi) = sc_crs.schnorr_prove(&origin_secret, &hat_secret);
    println!("------------------------------");
    println!("The ZoK Pi is {:?}", sc_pi);
    println!("The ZoK Hats_Pi is {:?}", hat_sc_pi);
    assert_eq!(sc_crs.schnorr_verify(&sc_pi, &hat_sc_pi), true);
    println!("-----------------------------");
    println!(
        "Pass the m-Schnorr proof : {}.\n",
        sc_crs.schnorr_verify(&sc_pi, &hat_sc_pi)
    );
    println!("Test m-Schnorr Done.");
}

#[test]
fn test_m_schnorr_batch() {
    let ntf_batch: Vec<(usize, usize, usize)> = vec![
/*        (16, 5, 5),
        (16, 10, 5),*/
        // (32, 10, 10),
        // (32, 20, 10),
        // (64, 21, 21),
        (64, 42, 21),(64, 42, 21)
/*        (128, 42, 42),
        (128, 84, 42),*/
    ];
    for (n, t, f) in ntf_batch {
        let max_m = if t > 10 { 10 } else { t };
        println!("===============================");
        println!("n = {}, t = {}, f = {}, max_m = {}", n, t, f, max_m);
        test_m_schnorr(n, t, f, max_m);
        println!("===============================");
    }
}

fn test_m_schnorr(n: usize, t: usize, f: usize, max_m: usize) {
    // Initialize Schnorr's CRS
    let loop_time=30usize;
    let sc_crs = KzgCrs::setup(t, f, n, "Test1", "Test2", "Test1", "Test2");
    let (mut gen, mut ver):(Vec<Vec<Duration>>,Vec<Vec<Duration>>)=(vec![vec![Duration::ZERO;loop_time+1];max_m+1],vec![vec![Duration::ZERO;loop_time+1];max_m+1]);
    for i in 0..loop_time {
        let mut rng = rand::rng();
        for m in 1..=max_m {
            // Randomly select a set of z and hat_z
            let mut origin_secret: Vec<Scalar> = Vec::with_capacity(m);
            let mut hat_secret: Vec<Scalar> = Vec::with_capacity(m);
            for _ in 0..m {
                origin_secret.push(Scalar::random(&mut rng));
                hat_secret.push(Scalar::random(&mut rng));
            }
            // Generate Schnorr proofs for z and hat_z
            let start = Instant::now();
            let (sc_pi, hat_sc_pi) = sc_crs.schnorr_prove(&origin_secret, &hat_secret);
            let end = start.elapsed();
            gen[m][0]+= end;
            gen[m][i+1]=end;
            // if i==99{
            //     println!("生成公钥数量m = {}", m);
            //     println!(
            //         "m-Schnorr证明生成时间: {} us, 证明内存占用: {} bytes",
            //         end.as_micros(),
            //         (G1Projective::COMPRESSED_BYTES
            //             + size_of::<Scalar>() * 2
            //             + size_of_val(&sc_pi.pk)
            //             + sc_pi.pk.len() * G1Projective::COMPRESSED_BYTES)
            //             * 2
            //     );
            // }

            assert_eq!(sc_crs.schnorr_verify(&sc_pi, &hat_sc_pi), true);

            let start = Instant::now();
            sc_crs.schnorr_verify(&sc_pi, &hat_sc_pi);
            let end = start.elapsed();
            ver[m][0]+= end;
            ver[m][i+1]=end;
            // if i == 99 {
            //     println!("m-Schnorr证明结果: {}, 证明时间: {} us", true, end.as_micros());
            // }
        }
    }
    for m in 1..=max_m {
        let (mean_gen_micros,mean_ver_micros,sd_gen,sd_ver) = calculate_std_dev(&gen[m],&ver[m],loop_time as u128);
        println!("生成公钥数量m = {}", m);
        println!(
            "m-Schnorr证明生成时间: {} us, 证明内存占用: {} bytes, 证明生成时间标准差: {} us",
            mean_gen_micros,
            (G1Projective::COMPRESSED_BYTES
                + size_of::<Scalar>() * 2
                + size_of::<Vec<G1Projective>>()
                + m * G1Projective::COMPRESSED_BYTES)
                * 2,
            sd_gen as u64
        );
        println!("m-Schnorr证明结果: {}, 证明时间: {} us, 证明验证时间标准差: {} us", true, mean_ver_micros, sd_ver as u64);
    }
}
fn calculate_std_dev(gen: &Vec<Duration>, ver: &Vec<Duration>, n:u128) -> (u128, u128 , f64, f64) {
    //计算平均数
    let mean_gen_micros:f64 = (gen[0].as_micros() /n) as f64;
    let mean_ver_micros:f64 = (ver[0].as_micros() /n) as f64;
    // println!("mean_gen_micros: {}, mean_ver_micros: {}", mean_gen_micros, mean_ver_micros);
    let mut temp_s_gen= 0f64;
    let mut temp_s_ver= 0f64;
    for i in 1..=n as usize{
        let diff_gen = gen[i].as_micros() as f64 - mean_gen_micros;
        let diff_ver = ver[i].as_micros() as f64 - mean_ver_micros;
        temp_s_gen += diff_gen * diff_gen;
        temp_s_ver += diff_ver * diff_ver;
    }
    let sd_gen = (temp_s_gen / ((n-1) as f64)).sqrt();
    let sd_ver = (temp_s_ver / ((n-1) as f64)).sqrt();
    // println!("sd_gen: {}, sd_ver: {}", sd_gen, sd_ver);
    (gen[0].as_micros() /n,ver[0].as_micros() /n,sd_gen,sd_ver)
}

#[test]
fn print_bytes(){
    println!(
        "G1Projective内存占用 {:?} bytes\n\
        Scalar内存占用 {:?} bytes",
        G1Projective::COMPRESSED_BYTES,size_of::<Scalar>()
    );
}