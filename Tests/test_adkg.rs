use bls12_381_plus::group::Curve;
use bls12_381_plus::{G1Projective, Scalar};
use rand::prelude::SliceRandom;
use std::collections::HashMap;
use std::sync::{mpsc, Arc};
use std::thread;
use zk_tool::*;

// ----------------------
// 1. Define parameters and data structures
// ----------------------
const N: usize = 16; // Total number of nodes
const T: usize = 5; // Reconstruction Threshold
const F: usize = 5; // Malicious Node

#[derive(Debug, Clone)]
struct PolyPcs {
    alpha_poly: Vec<Scalar>,
    hat_alpha_poly: Vec<Scalar>,
    cm: Vec<G1Projective>,
}
// Simulated network transmission message packets
struct ShareMessage {
    sender_id: usize,
    share_data: PolyPcs,
}

#[test]
fn test_adkg() {
    println!(
        "=== ADKG Simulation system startup (N={}, T={}, F={}) ===",
        N, T, F
    );
    // 1. Initialize KZG commitment CRS
    // "Test1", "Test2", "Test3", and "Test4" are the default test parameters, which can be changed arbitrarily.
    let kzg_crs = KzgCrs::setup(T, F, N, "Test1", "Test2", "Test3", "Test4");
    let kzg_shared = Arc::new(kzg_crs);
    // 2. Initialize network channel
    // Create a (Sender, Receiver) pair for each node
    // channels[i] corresponds to the node with ID = i+1
    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    for _ in 0..N {
        let (tx, rx) = mpsc::channel::<ShareMessage>();
        senders.push(tx);
        receivers.push(rx);
    }
    // 3. Create N threads and distribute tasks
    let mut handles = Vec::new();
    for i in 0..N {
        let kzg_crs_thread = kzg_shared.clone();
        let node_id = i + 1;
        // Retrieve the receivers belonging to this node in order
        // (remove(0) will pop them out one by one).
        let my_rx = receivers.remove(0);
        // Clone a list of all network senders to this thread.
        let cluster_txs = senders.clone();
        let handle = thread::spawn(move || {
            // A. Generating polynomials
            let (u_matrix, hat_u_matrix, vander_matrix) =
                bi_polynomial::gen_polynomial_random(T, F, N);
            let (mut alpha_matrix, mut hat_alpha_matrix) =
                bi_polynomial::bi2alpha(&u_matrix, &hat_u_matrix, &vander_matrix, N);
            let total_commitment = kzg_crs_thread.bi_commit(&u_matrix, &hat_u_matrix);
            // B. Sending phase: Traverse all nodes and send Share
            for (target_idx, tx) in cluster_txs.iter().enumerate() {
                let target_id = target_idx + 1;
                let share_val = PolyPcs {
                    alpha_poly: alpha_matrix[target_id].clone(),
                    hat_alpha_poly: hat_alpha_matrix[target_id].clone(),
                    cm: total_commitment.clone(),
                };
                let _ = tx.send(ShareMessage {
                    sender_id: node_id,
                    share_data: share_val.clone(),
                });
            }
            // C. Receiving phase: Collect N Shares from other users.
            let mut received_cm = HashMap::new();
            for _ in 0..N {
                if let Ok(msg) = my_rx.recv() {
                    let sep_cm = kzg_crs_thread.divide_com(&msg.share_data.cm, &vander_matrix);
                    let temp_cm = kzg_crs_thread
                        .uni_commit(&msg.share_data.alpha_poly, &msg.share_data.hat_alpha_poly);
                    if sep_cm[node_id] == temp_cm {
                        alpha_matrix[msg.sender_id] = msg.share_data.alpha_poly.clone();
                        hat_alpha_matrix[msg.sender_id] = msg.share_data.hat_alpha_poly.clone();
                        received_cm.insert(msg.sender_id, sep_cm);
                    }
                }
            }
            // D. Returns its own ID and a polynomial for later use by the main thread.
            (node_id, alpha_matrix, hat_alpha_matrix, received_cm)
        });
        handles.push(handle);
    }
    // 4. Main thread aggregation results
    // Wait for all threads to complete, and then store the results in a Map for later indexing by ID.
    let mut node_states: HashMap<
        usize,
        (
            Vec<Vec<Scalar>>,
            Vec<Vec<Scalar>>,
            HashMap<usize, Vec<G1Projective>>,
        ),
    > = HashMap::new();
    for handle in handles {
        // Reclaim data from each thread
        let (id, alpha_matrix, hat_alpha_matrix, cm) = handle.join().unwrap();
        node_states.insert(id, (alpha_matrix, hat_alpha_matrix, cm));
    }
    println!(
        "-> All nodes have completed their calculations, and the main thread has been recycled."
    );
    // 5. Random function generates a set.
    let fid = random_unique_numbers(N, F + 1);
    println!("-> Generate a set of Dealers (size {}): {:?}", F + 1, fid);
    // 6. Randomly generate two sets t+1 and calculate
    // Generate tid0 and tid1 (size t+1).
    let tid0 = random_unique_numbers(N, T + 1);
    let tid1 = random_unique_numbers(N, T + 1);
    println!("-> Generate the tid0 set (size {}): {:?}", T + 1, tid0);
    println!("-> Generate the tid1 set (size {}): {:?}", T + 1, tid1);
    // 7. Read the secret share of the specified ID and perform calculations.
    let pk0 = pk_generator(&kzg_shared.clone(), &tid0, &fid, &node_states);
    let pk1 = pk_generator(&kzg_shared.clone(), &tid1, &fid, &node_states);
    println!("The public key generated by tid0 is {:?}", pk0.to_affine());
    println!("The public key generated by tid1 is {:?}", pk1.to_affine());
    assert_eq!(pk0, pk1);
    if pk0.eq(&pk1) {
        println!("Different nodes can participate to generate the same public key.\n");
    }
    println!("Test ADKG Done.");
}

// Simulate Schnorr protocol message structure
struct ProofMessage {
    sender_id: usize,
    sc_pi: SchnorrPi,
    hat_sc_pi: SchnorrPi,
}

fn pk_generator(
    sc_crs: &KzgCrs,
    group_ids: &Vec<usize>,
    fid: &Vec<usize>,
    all_nodes_data: &HashMap<
        usize,
        (
            Vec<Vec<Scalar>>,
            Vec<Vec<Scalar>>,
            HashMap<usize, Vec<G1Projective>>,
        ),
    >,
) -> G1Projective {
    let group_size = group_ids.len();
    println!(
        "\n--- Commencing the public key generation phase (number of participating nodes: {}) ---",
        group_size
    );
    // 1. Establish an internal communication network for the current group.
    let (senders, mut receivers): (Vec<_>, Vec<_>) = (0..group_size)
        .map(|_| mpsc::channel::<ProofMessage>())
        .unzip();
    let mut handles = Vec::new();
    let temp_sc_crs = sc_crs.clone();
    let sc_shared = Arc::new(temp_sc_crs);
    // 2. Iterate through each node in the group and start a thread.
    for (_idx, &node_id) in group_ids.iter().enumerate() {
        // Prepare thread parameters
        let my_rx = receivers.remove(0);
        let cluster_txs = senders.clone();
        let fid_clone = fid.clone();
        let sc_crs_thread = sc_shared.clone();
        let (alpha_matrix, hat_alpha_matrix, _cm) = all_nodes_data.get(&node_id).unwrap().clone();
        let handle = thread::spawn(move || {
            // A. Selection and Calculation
            // Read the corresponding polynomial based on the id in fid.
            let (mut zk, mut hat_zk) = (Scalar::ZERO, Scalar::ZERO);
            for &f_id in &fid_clone {
                let (alpha, hat_alpha) =
                    (alpha_matrix[f_id].clone(), hat_alpha_matrix[f_id].clone());
                zk += alpha[0]; // Calculate private key share zk
                hat_zk += hat_alpha[0]; // Calculate hat_zk to complete Schnorr
            }
            // Construct an array to be used as input for Schnorr prove.
            let z = vec![zk; 1];
            let hat_z = vec![hat_zk; 1];
            let my_proof = sc_crs_thread.schnorr_prove(&z, &hat_z);
            // B. Broadcast
            for tx in &cluster_txs {
                let _ = tx.send(ProofMessage {
                    sender_id: node_id,
                    sc_pi: my_proof.0.clone(),
                    hat_sc_pi: my_proof.1.clone(),
                });
            }

            // C. Receiving and collecting
            let mut collected_pk_share = Vec::new();
            // Waiting to receive messages from everyone in the group
            for _ in 0..cluster_txs.len() {
                if let Ok(msg) = my_rx.recv() {
                    if sc_crs_thread.schnorr_verify(&msg.sc_pi, &msg.hat_sc_pi) {
                        // If the verification passes, then save it.
                        collected_pk_share
                            .push((Scalar::from(msg.sender_id as u64), msg.sc_pi.pk[0].clone()));
                    }
                }
            }
            // D. Public key calculated by interpolation
            let result = bi_polynomial::interpolate_poly_g1(&collected_pk_share);
            // 返回结果
            result[0]
        });

        handles.push(handle);
    }

    // 3. The main thread waits for all results in this group.
    let mut group_results = Vec::new();
    for handle in handles {
        group_results.push(handle.join().unwrap());
    }
    println!("Complete.\nNode results: {:?}\n", group_results[0]);
    group_results[0]
}

fn random_unique_numbers(n: usize, count: usize) -> Vec<usize> {
    // Randomly generate count of IDs
    let mut numbers: Vec<usize> = (1..=n).collect();
    let mut rng = rand::rng();
    numbers.shuffle(&mut rng);
    numbers.truncate(count);
    numbers
}
