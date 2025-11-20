use bls12_381_plus::elliptic_curve::Field;
use bls12_381_plus::Scalar;
use zk_tool::*;

#[test]
fn test_m_schnorr() {
    let (n, t, f, m): (usize, usize, usize, usize) = (16, 5, 5, 2);
    let mut rng = rand::thread_rng();
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
