mod dsa_ecc;
mod ies_ecc;
mod our_fdgs;
mod utils;
mod accumulator;
mod zkp;

use p256::{ecdsa::{SigningKey, Signature, signature::Signer, VerifyingKey, signature::Verifier}};
use std::time::{Duration, Instant};

use dsa_ecc::{keyGen_Signature, sig, vf};
use ies_ecc::{keyGen_Encryption, enc, dec};
use our_fdgs::{GSetup, GKGen, UKGen, Join_Issue, GUpdate, Sign, Verify, Trace, Judge};
use utils::{hex_string_to_signature};
use accumulator::{TAcc, TWitness, TVerify, TUpdate};

fn main() {
    let message = "Hello, I am Tu from Ho Chi Minh city, Viet Nam.".to_string();

    // Test ECDSA
    /*let (signing_key, verify_key) = keyGen_Signature();
    let signature = sig(signing_key.clone(), message.clone());
    let ok = vf(verify_key.clone(), message.clone(), signature.clone());
    println!("{:?}", ok.clone());*/

    // Test ECIES
    /*let (sk, pk) = keyGen_Encryption();
    let ciphertext = enc(pk.clone(), message.clone());
    println!("Ciphertext: {:x?}", hex::encode(ciphertext.clone()));
    let recover_msg = dec(sk.clone(), ciphertext.clone());
    println!("Message 2: {:x?}", recover_msg.clone());*/

    // Test Dynamic Merkle-Tree Accumulator
    /*let P = vec!["123".to_string(), "0".to_string(), "24".to_string(), "23".to_string(), "2233".to_string(), "ffr3".to_string(), "6ab".to_string(), "2323dff".to_string()];
    let (mut mk_tree, mut root) = TAcc(P.clone());
    println!("Merkle Tree = {:?}", mk_tree);
    let (bin_idx_old, witness_old) = TWitness(mk_tree.clone(), P[5].clone());
    if bin_idx_old != "".to_string() {
        println!("\nidx = {:?}", bin_idx_old.clone());
        println!("w = {:?}", witness_old.clone());
    } else {
        println!{"Can not extract witness"};
    }

    if bin_idx_old != "".to_string() {
        let ok = TVerify(root, P[5].clone(), (bin_idx_old.clone(), witness_old.clone()));
        println!("{}", ok);

        root = TUpdate(&mut mk_tree, "111".to_string(), "id01".to_string());
        println!("\nNew Merkle Tree = {:?}", mk_tree);
        println!("New root = {:?}", root);
    }*/

    // Fully Dynamic Group Signature
    let mut time_gsetup = Duration::new(0, 0);
    let mut time_gkgen = Duration::new(0, 0);
    let mut time_ukgen = Duration::new(0, 0);
    let mut time_joinissue = Duration::new(0, 0);
    let mut time_gupdate = Duration::new(0, 0);
    let mut time_sign = Duration::new(0, 0);
    let mut time_trace = Duration::new(0, 0);
    let mut time_judge = Duration::new(0, 0);

    let n_loop = 1;
    for run_idx in 0..n_loop.clone() {
        let start_gsetup = Instant::now();
        let (N, d) = GSetup();
        let duration_gsetup = start_gsetup.elapsed();
        time_gsetup += duration_gsetup;

        let start_gkgen = Instant::now();

        // gpk = (N, d, pk_e, pk_s)
        let ((N, d, pk_e, pk_s), (mut u, mut w), sk_e, (sk_s, mut reg, mut merkle_tree, mut c)) = GKGen(N, d);
        // println!("{:?}, {:?}, {:?}, {:?}", N, d, pk_e.serialize(), pk_s.to_encoded_point(false)); // size of gpk
        let duration_gkgen = start_gkgen.elapsed();
        time_gkgen += duration_gkgen;

        // Create key for several users
        let mut gsk: Vec<(usize, VerifyingKey, SigningKey, Signature)> = Vec::new();
        let mut usk: Vec<SigningKey> = Vec::new();
        let mut upk: Vec<VerifyingKey> = Vec::new();
        let start_ukgen = Instant::now();
        for i in 0..250 {
            let (usk_temp, upk_temp) = UKGen();
            usk.push(usk_temp);
            upk.push(upk_temp);
        }
        let duration_ukgen = start_ukgen.elapsed();
        time_ukgen += duration_ukgen;

        // Test <Join, Issue>
        let start_joinissue = Instant::now();
        for i in 0..250 {
            gsk.push(Join_Issue(N, d, (usk[i].clone(), upk[i].clone()), (&mut c, sk_s.clone(), &mut reg, &mut merkle_tree), (&mut u, &mut w)));
        }
        let duration_joinissue = start_joinissue.elapsed();
        time_joinissue += duration_joinissue;
        // println!("{:?}", d + (gsk[0].1.to_encoded_point(false).len() + gsk[0].2.to_bytes().len()) * 8 + 4 * hex::encode(gsk[0].3).len());
        /*for i in 0..w.len() {
            println!("{:?}", w[i].clone());
        }*/
        // Check if user can not join in a group
        /*let (usk5, upk5) = UKGen();
        let unable_join = Join_Issue(N, d, (usk5, upk5), (&mut c, sk_s.clone(), &mut reg, &mut merkle_tree), (&mut u, &mut w));
        if unable_join.0 == N {
            println!("User can not join");
        }*/

        // Test GUpdate
        let mut S: Vec<String> = Vec::new();
        /*for i in 87..125 {
            S.push(hex::encode(gsk[i].1.to_encoded_point(false)));
        }
        for i in 142..196 {
            S.push(hex::encode(gsk[i].1.to_encoded_point(false)));
        }
        for i in 221..229 {
            S.push(hex::encode(gsk[i].1.to_encoded_point(false)));
        }*/
        // println!("- The number of revoked users: {}", S.len());
        let start_gupdate = Instant::now();
        GUpdate(N, d, &mut merkle_tree, S.clone(), (&mut u, &mut w));
        let duration_gupdate = start_gupdate.elapsed();
        time_gupdate += duration_gupdate;
        /*let mut total_size = 0;
        for i in 0..merkle_tree.len() {
            total_size += 4 * merkle_tree[i].clone().len();
        }
        println!("{:?}", total_size);*/
        /*println!("{:?}", u);
        let mut total_size = 256;
        for i in 0..w.len() {
            total_size += w[i].0.clone().len();
            for j in 0..w[i].1.clone().len() {
                total_size += w[i].1[j].clone().len() * 4;
            }
            // println!("{:?}", w[i].clone());
        }
        println!("{:?}", total_size);*/
        /*let mut total_size = 0;
        for i in 0..w[0].1.clone().len() {
            total_size += 4 * w[0].1[i].clone().len();
        }
        println!("{:?}", total_size);*/

        // Sign & Verify
        let idx_sign = 2;
        let start_sign = Instant::now();
        let g_sig = Sign(N, d, pk_e, pk_s, gsk[idx_sign].clone(), (u.clone(), w.clone()), message.clone());
        let duration_sign = start_sign.elapsed();
        time_sign += duration_sign;
        // println!("Sign: {:?}", duration_sign);
        // println!("- Group signature: {:?}", g_sig);
        /*if g_sig.0 == Vec::new() {
            println!("Can not create a group signature");
        }*/
        println!("- Verify a group signature: {}", Verify(N, d, pk_e, pk_s, (u.clone(), w.clone()), message.clone(), g_sig.clone()));

        // Trace and Judge
        let start_trace = Instant::now();
        let id_signer = Trace(N, d, pk_e, pk_s, sk_e, (u.clone(), w.clone()), reg, message.clone(), g_sig.clone());
        let duration_trace = start_trace.elapsed();
        time_trace += duration_trace;
        // println!("Trace: {:?}", duration_trace);
        // println!("- Trace information: {:?}", id_signer);
        /*if id_signer.0 == N {
            println!("Can not trace this group signature");
        }*/
        let start_judge = Instant::now();
        let ok_judge = Judge(N, d, pk_e, pk_s, id_signer.clone().0, (u.clone(), w.clone()), upk[id_signer.clone().0].clone(), message.clone(), g_sig.clone(), id_signer.clone().1);
        let duration_judge = start_judge.elapsed();
        time_judge += duration_judge;
        // println!("Judge: {:?}", duration_judge);
        println!("- Judge an identity for a group signature: {:?}", ok_judge);

        // Debug to fix bug
        /*let (sk, pk) = keyGen_Signature();
        let test_sig = sig(sk, message);
        println!("{:?}", test_sig);
        let str_test_sig = hex::encode(test_sig);
        println!("{:?}", str_test_sig);
        let test_sig_decode = hex::decode(str_test_sig.clone()).expect("");
        println!("{:?}", test_sig_decode);
        let test_sig_2 = hex_string_to_signature(&str_test_sig).expect("");
        println!("{:?}", test_sig_2);*/
    }

    println!("GSetup: {:?}", time_gsetup / n_loop.clone());
    println!("GKGen: {:?}", time_gkgen / n_loop.clone());
    println!("UKGen: {:?}", time_ukgen / n_loop.clone());
    println!("Join & Issue: {:?}", time_joinissue / n_loop.clone());
    println!("GUpdate: {:?}", time_gupdate / n_loop.clone());
    println!("Sign: {:?}", time_sign / n_loop.clone());
    println!("Trace: {:?}", time_trace / n_loop.clone());
    println!("Judge: {:?}", time_judge / n_loop.clone());
}