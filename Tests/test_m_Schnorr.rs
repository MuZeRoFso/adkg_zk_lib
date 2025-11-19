use bls12_381_plus::elliptic_curve::Field;
use bls12_381_plus::Scalar;
use bi_polynomial::*;
use zk_tool::*;

#[test]
fn test_m_schnorr() {
    // 定义ntfm和随机生成器
    let (n,t,f,m):(usize,usize,usize,usize) = (16,5,5,2);
    let mut rng = rand::thread_rng();
    // 初始化Schnorr的CRS
    let sc_crs=KzgCrs::setup(t,f,n,"Test1","Test2","Test3","Test4");
    // 随机一组z和hat_z
    let mut origin_secret: Vec<Scalar>=Vec::with_capacity(m);
    let mut hat_secret:Vec<Scalar>=Vec::with_capacity(m);
    for _ in 0..m {
        origin_secret.push(Scalar::random(&mut rng));
        hat_secret.push(Scalar::random(&mut rng));
    }
    println!("The secrets are {:?} (Hex).",origin_secret);
    println!("The hats are {:?} (Hex).",hat_secret);
    //对z和hat_z生成Schnorr证明
    let (sc_pi,hat_sc_pi)=sc_crs.schnorr_prove(&origin_secret,&hat_secret);

    println!("The ZoK Pi is {:?}",sc_pi);
    println!("The ZoK Hats_Pi is {:?}",hat_sc_pi);

    assert_eq!(sc_crs.schnorr_verify(&sc_pi,&hat_sc_pi),true);
    println!("Pass the m-Schnorr proof : {}.",sc_crs.schnorr_verify(&sc_pi,&hat_sc_pi));
}