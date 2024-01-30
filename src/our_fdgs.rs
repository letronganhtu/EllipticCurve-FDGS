use p256::{ecdsa::{SigningKey, VerifyingKey, Signature}};
use ecies::{PublicKey, SecretKey};

use crate::dsa_ecc::{keyGen_Signature, sig, vf};
use crate::ies_ecc::{keyGen_Encryption, enc, dec};
use crate::accumulator::{TAcc, TWitness, TUpdate};
use crate::utils::{hex_string_to_signature};
use crate::zkp::{P1, V1, P2, V2};

pub fn GSetup() -> (usize, usize) {
    let d = 16; // Changeable, depend on yours (d > 0)
    return (1 << d, d);
}

pub fn GKGen(N: usize, d: usize) -> ((usize, usize, PublicKey, VerifyingKey), (String, Vec<(String, Vec<String>)>), SecretKey, (SigningKey, Vec<Vec<String>>, Vec<String>, usize)) {
    // Generate key for GM and TM
    let (sk_s, pk_s) = keyGen_Signature();
    let (sk_e, pk_e) = keyGen_Encryption();

    // Paramaters for Group Information
    let reg = vec![vec!["0".to_string(); 2]; N]; // N rows, 2 cols
    let list_of_pk = vec!["0".to_string(); N];
    let (mk_tree, root) = TAcc(list_of_pk);
    let c: usize = 0;
    let current_user: Vec<(String, Vec<String>)> = Vec::new();

    // [Public(Group public key - Group info) - Private of TM - Private of GM]
    return ((N, d, pk_e, pk_s), (root, current_user), sk_e, (sk_s, reg, mk_tree, c));
}

pub fn UKGen() -> (SigningKey, VerifyingKey) {
    return keyGen_Signature();
}

pub fn Join_Issue(N: usize, d: usize, (usk, upk): (SigningKey, VerifyingKey), (c, sk_s, reg, merkle_tree): (&mut usize, SigningKey, &mut Vec<Vec<String>>, &mut Vec<String>), (u, w): (&mut String, &mut Vec<(String, Vec<String>)>)) -> (usize, VerifyingKey, SigningKey, Signature) {
    let (new_usk, new_upk) = keyGen_Signature();
    let new_upk_string = hex::encode(new_upk.to_encoded_point(false));
    let sig_user = sig(usk.clone(), new_upk_string.clone());

    if vf(upk, new_upk_string.clone(), sig_user.clone()) == true && c.clone() < N {
        let i = c.clone();
        *c += 1;
        // println!("Registed User = {}", c);
        // println!("Idx = {}", i);
        let cert = sig(sk_s, i.to_string() + &new_upk_string);
        // println!("{:?}", hex::encode(cert));
        reg[i][0] = new_upk_string.clone();
        reg[i][1] = hex::encode(sig_user.clone());
        let mut bin_idx = format!("{:0b}", i);
        while bin_idx.len() != d {
            bin_idx = "0".to_owned() + &bin_idx;
        }
        *u = TUpdate(merkle_tree, bin_idx, new_upk_string.clone());
        for i in 0..w.len() {
            let idx = usize::from_str_radix(&w[i].0.clone(), 2).unwrap();
            let (bin_idx, witness) = TWitness(merkle_tree.clone(), merkle_tree[(1 << d) - 1 + idx].clone());
            w[i] = (bin_idx, witness);
        }
        let (bin_idx, witness) = TWitness(merkle_tree.clone(), new_upk_string.clone());
        w.push((bin_idx, witness));

        return (i, new_upk, new_usk, cert);
    }

    return (N, upk, usk.clone(), sig(usk.clone(), "Fail".to_string()));
}

pub fn GUpdate(N: usize, d: usize, merkle_tree: &mut Vec<String>, S: Vec<String>, (u, w): (&mut String, &mut Vec<(String, Vec<String>)>)) {
    if S.len() > 0 {
        for x in S {
            for idx in 0..N {
                if x == merkle_tree[(1 << d) - 1 + idx] {
                    let mut bin_idx = format!("{:0b}", idx);
                    while bin_idx.len() != d {
                        bin_idx = "0".to_owned() + &bin_idx;
                    }
                    // Update Merkle tree
                    *u = TUpdate(merkle_tree, bin_idx.clone(), "0".to_string());

                    // Remove witness of revoked user
                    for i in 0..w.len() {
                        if w[i].0 == bin_idx.clone() {
                            w.remove(i);
                            break;
                        }
                    }
                }
            }
        }

        // Update witness for active user
        for i in 0..w.len() {
            let idx = usize::from_str_radix(&w[i].0.clone(), 2).unwrap();
            let (bin_idx, witness) = TWitness(merkle_tree.clone(), merkle_tree[(1 << d) - 1 + idx].clone());
            w[i] = (bin_idx, witness);
        }
    }
}

pub fn Sign(N: usize, d: usize, pk_e: PublicKey, pk_s: VerifyingKey, (i, pk_i, sk_i, cert_i): (usize, VerifyingKey, SigningKey, Signature), (u, w): (String, Vec<(String, Vec<String>)>), m: String) -> (Vec<u8>, String) {
    let mut bin_idx = format!("{:0b}", i);
    while bin_idx.len() != d {
        bin_idx = "0".to_owned() + &bin_idx;
    }

    // Check if user is active
    let mut witness: (String, Vec<String>) = ("0".to_string(), vec!["0".to_string()]);
    for x in w.clone() {
        if bin_idx.clone() == x.clone().0 {
            witness = x.clone();
            break;
        }
    }
    if witness == ("0".to_string(), vec!["0".to_string()]) {
        return (Vec::<u8>::new(), "".to_string());
    }

    // Create a group signature
    let group_signature = sig(sk_i, m.clone());
    let msg_to_encrypt = bin_idx + ";" + &hex::encode(pk_i.clone().to_encoded_point(false)) + ";" + &hex::encode(cert_i.clone()) + ";" + &hex::encode(group_signature.clone());
    let enc_id = enc(pk_e, msg_to_encrypt.clone());

    // ZKProof (Prover): P1(public parameters, private parameters)
    let pi_1 = P1((pk_e, pk_s, m, enc_id.clone(), u), (i, pk_i, cert_i, group_signature, witness.1));

    return (enc_id, pi_1);
}

pub fn Verify(N: usize, d: usize, pk_e: PublicKey, pk_s: VerifyingKey, (u, w): (String, Vec<(String, Vec<String>)>), m: String, (c, pi_1): (Vec<u8>, String)) -> bool {
    return V1(pk_e, pk_s, m, c, u);
}

pub fn Trace(N: usize, d: usize, pk_e: PublicKey, pk_s: VerifyingKey, sk_e: SecretKey, (u, w): (String, Vec<(String, Vec<String>)>), reg: Vec<Vec<String>>, m: String, (c, pi_1): (Vec<u8>, String)) -> (usize, Option<(VerifyingKey, Signature, usize, VerifyingKey, Signature, Signature, String)>) {
    let dec_id = dec(sk_e, c.clone());
    let id: Vec<&str> = dec_id.as_str().splitn(4, ';').collect();
    
    let mut ok: bool = false;
    for x in w {
        if x.0 == id[0].to_string() {
            ok = true;
            break;
        }
    }
    if ok == false {
        return (N, None);
    }

    let idx = usize::from_str_radix(&id[0].clone(), 2).unwrap();
    let (pk_i, sig_i) = (reg[idx][0].clone(), reg[idx][1].clone());
    if pk_i == "0".to_string() || pk_i != id[1].to_string() {
        return (N, None);
    }

    if V1(pk_e, pk_s, m, c.clone(), u) == false {
        return (N, None);
    }

    let verifying_key_bytes = hex::decode(id[1].clone()).expect("");
    let pi_2 = P2((pk_e, c, idx, VerifyingKey::from_sec1_bytes(&verifying_key_bytes).expect(""), hex_string_to_signature(id[2].clone()).expect(""), hex_string_to_signature(id[3].clone()).expect("")), sk_e.clone());
    let pk_bytes = hex::decode(pk_i.clone()).expect("");
    let beta = (VerifyingKey::from_sec1_bytes(&pk_bytes).expect(""), hex_string_to_signature(&sig_i.clone()).expect(""), idx, VerifyingKey::from_sec1_bytes(&verifying_key_bytes).expect(""), hex_string_to_signature(id[2].clone()).expect(""), hex_string_to_signature(id[3].clone()).expect(""), pi_2);

    return (idx, Some(beta));
}

pub fn Judge(N: usize, d: usize, pk_e: PublicKey, pk_s: VerifyingKey, i: usize, (u, w): (String, Vec<(String, Vec<String>)>), upk_i: VerifyingKey, m: String, (c, pi_1): (Vec<u8>, String), beta: Option<(VerifyingKey, Signature, usize, VerifyingKey, Signature, Signature, String)>) -> bool {
    if i == N && beta == None {
        return !V1(pk_e, pk_s, m, c, u);
    }
    
    let Some((pk_h, sig_h, idx, pk, cert, s, pi_2)) = beta else { return false; };
    if V2(pk_e, c, idx, pk, cert, s) == false {
        return false;
    }

    if i == idx && pk == pk_h && vf(upk_i, hex::encode(pk_h.to_encoded_point(false)), sig_h) == true {
        return true;
    }
    return false;
}