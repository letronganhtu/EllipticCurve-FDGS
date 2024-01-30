use sha2::{Sha256, Digest};

// TSetup -> SHA256

// Assume P.len() = 2^d where d is a positive integer
pub fn TAcc(P: Vec<String>) -> (Vec<String>, String) {
    let mut merkle_tree = vec!["0".to_string(); P.len() * 2 - 1];
    let d = (P.len() as f32).log2() as usize;
    
    let mut i = d;
    while i > 0 {
        let mut j = 0;
        while j < (1 << i) {
            if i == d {
                merkle_tree[(1 << i) - 1 + j] = P[j].clone();
            } else {
                let mut hasher = Sha256::new();
                hasher.update(merkle_tree[2 * ((1 << i) - 1 + j) + 1].clone());
                hasher.update(merkle_tree[2 * ((1 << i) - 1 + j) + 2].clone());
                merkle_tree[(1 << i) - 1 + j] = format!("{:x}", hasher.finalize());
            }
            j += 1;
        }
        i -= 1;
    }

    let mut hasher = Sha256::new();
    hasher.update(merkle_tree[1].clone());
    hasher.update(merkle_tree[2].clone());
    merkle_tree[0] = format!("{:x}", hasher.finalize());

    return (merkle_tree.clone(), merkle_tree[0].clone());
}

pub fn TWitness(merkle_tree: Vec<String>, p: String) -> (String, Vec<String>) {
    let d = (((merkle_tree.len() + 1) as f32).log2() - 1.0) as usize;
    let mut idx: usize = 1 << d;
    for i in ((1 << d) - 1)..((1 << (d + 1)) - 1) {
        if p == merkle_tree[i] {
            idx = i + 1 - (1 << d);
            break;
        }
    }

    if idx == (1 << d) {
        return ("".to_string(), Vec::new());
    } else {
        let mut bin_idx = format!("{:0b}", idx);
        while bin_idx.len() != d {
            bin_idx = "0".to_owned() + &bin_idx;
        }

        let mut cur_idx = (1 << d) - 1 + idx;
        let mut run_idx = d - 1;
        let mut witness = Vec::new();
        while run_idx >= 0 {
            if bin_idx.as_bytes()[run_idx] == b'0' {
                witness.push(merkle_tree[cur_idx + 1].clone());
            } else {
                witness.push(merkle_tree[cur_idx - 1].clone());
            }
            cur_idx = (cur_idx - 1) >> 1;
            if run_idx == 0 {
                break;
            }
            run_idx -= 1;
        }
        return (bin_idx, witness);
    }
}

pub fn TVerify(u: String, p: String, (bin_idx, witness): (String, Vec<String>)) -> bool {
    let mut v = p;
    let mut i = bin_idx.len() - 1;
    let d = bin_idx.len();

    while i >= 0 {
        let mut hasher = Sha256::new();
        if bin_idx.as_bytes()[i] == b'0' {
            hasher.update(v);
            hasher.update(witness[d - i - 1].clone());
        } else {
            hasher.update(witness[d - i - 1].clone());
            hasher.update(v);
        }
        v = format!("{:x}", hasher.finalize());

        if i == 0 {
            break;
        }
        i -= 1;
    }

    return u == v;
}

pub fn TUpdate(merkle_tree: &mut Vec<String>, bin_idx: String, p_new: String) -> String {
    let mut i = bin_idx.len() - 1;
    let d = bin_idx.len();
    
    let idx = usize::from_str_radix(&bin_idx, 2).unwrap();
    let mut mktree_idx = (1 << d) - 1 + idx;

    let mut bin_idx = format!("{:0b}", idx);
    while bin_idx.len() != d {
        bin_idx = "0".to_owned() + &bin_idx;
    }

    let mut cur_idx = (1 << d) - 1 + idx;
    let mut run_idx = d - 1;
    let mut witness = Vec::new();
    while run_idx >= 0 {
        if bin_idx.as_bytes()[run_idx] == b'0' {
            witness.push(merkle_tree[cur_idx + 1].clone());
        } else {
            witness.push(merkle_tree[cur_idx - 1].clone());
        }
        cur_idx = (cur_idx - 1) >> 1;
        if run_idx == 0 {
            break;
        }
        run_idx -= 1;
    }

    if TVerify(merkle_tree[0].clone(), merkle_tree[mktree_idx].clone(), (bin_idx.clone(), witness.clone())) == false {
        return merkle_tree[0].clone();
    }

    let mut v = p_new.clone();
    merkle_tree[mktree_idx] = p_new.clone();

    while i >= 0 {
        let mut hasher = Sha256::new();
        if bin_idx.as_bytes()[i] == b'0' {
            hasher.update(v);
            hasher.update(witness[d - i - 1].clone());
        } else {
            hasher.update(witness[d - i - 1].clone());
            hasher.update(v);
        }
        v = format!("{:x}", hasher.finalize());
        
        mktree_idx = (mktree_idx - 1) >> 1;
        merkle_tree[mktree_idx] = v.clone();

        if i == 0 {
            break;
        }
        i -= 1;
    }

    return merkle_tree[0].clone();
}