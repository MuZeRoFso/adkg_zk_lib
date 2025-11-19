use bi_polynomial::*;
use zk_tool::*;
use bls12_381_plus::Scalar;
use rand::Rng;
use rand::seq::SliceRandom;

#[test]
fn test_secret_sharing() {
    //先定ntf
    let (n,t,f):(usize,usize,usize)=(16,5,5);
    //定秘密 如果没有映射方法就定一个数
    let mut origin_secret: Vec<Scalar>=Vec::with_capacity(1);
    origin_secret.push(Scalar::from(10000u64));
    //用gen_polynomial_with_secret构建，并返回双矩阵，再使用bi2alpha，返回alpha矩阵
    let (u_matrix,hat_u_matrix,vander_matrix)
        =bi_polynomial::gen_polynomial_with_secret(t,f,n,&origin_secret);
    println!("The secret is {:?} (Hex).",u_matrix[0][0]);
    let (alpha_matrix, hat_alpha_matrix)=bi_polynomial::bi2alpha(&u_matrix, &hat_u_matrix, &vander_matrix, n);
    //调用kzg的setup，输入四句话
    let kzg_crs=KzgCrs::setup(t,f,n,"Test1","Test2","Test3","Test4");
    //println!("{:?}", kzg_crs);
    // 使用bi_commit进行总体承诺
    let total_commitment=kzg_crs.bi_commit(&u_matrix,&hat_u_matrix);
    //以上是Dealer做的事

    //模拟某个随机节点接收到数据，例如id=i
    let mut rng=rand::thread_rng();
    let id: usize = rng.gen_range(1..=n);
    println!("Random id is {:?}.",id);
    //假设拿到了总体承诺，使用Divide_com分开
    let sep_cm=kzg_crs.divide_com(&total_commitment,&vander_matrix);
    //假设拿到了alpha i，然后进行验证，并且确认验证通过
    let (alpha_id,hat_alpha_id)
        =(alpha_matrix[id].clone(),hat_alpha_matrix[id].clone());
    let temp_cm=kzg_crs.uni_commit(&alpha_id,&hat_alpha_id);
    assert_eq!(temp_cm,sep_cm[id],"Error! {:?} is NOT EQUAL to {:?}",temp_cm,sep_cm[id]);
    println!("alpha_{} 和 hat_alpha_{} 验证通过",id,id);

    //随机一组t个节点，演示秘密恢复
    let random_id=random_unique_numbers(n,t+1);
    println!("Random id are {:?}.",random_id);
    let mut accept_points:Vec<(Scalar,Scalar)>=Vec::with_capacity(t+1);
    // accept收集这些节点的alpha(0)用作恢复。
    for i in 0..random_id.len(){
        let x:u64= random_id[i] as u64;
        accept_points.push((Scalar::from(x), alpha_matrix[random_id[i]][0]));
    }
    println!("Accept points are {:?}.",accept_points);
    let temp_secret=interpolate_poly_scalar(&accept_points);
    assert_eq!(origin_secret[0],temp_secret[0],"Error!{:?} is NOT EQUAL to {:?}",origin_secret,temp_secret);
    println!("origin_secret={:?}",origin_secret);
    println!("temp_secret={:?}",temp_secret);
    //结束通过
}

fn random_unique_numbers(n: usize, t: usize) -> Vec<usize> {
    // 随机出t个id
    let mut numbers: Vec<usize> = (1..=n).collect();
    let mut rng = rand::thread_rng();
    numbers.shuffle(&mut rng);
    numbers.truncate(t);
    numbers
}