use ecies::{utils::generate_keypair, encrypt, decrypt, PublicKey, SecretKey};

pub fn keyGen_Encryption() -> (SecretKey, PublicKey) {
    return generate_keypair();
}

pub fn enc(pk: PublicKey, message: String) -> Vec<u8> {
    // println!("Ciphertext: {:x?}", hex::encode(ciphertext.clone()));
    return encrypt(&pk.serialize(), message.as_bytes()).unwrap();
}

pub fn dec(sk: SecretKey, ciphertext: Vec<u8>) -> String {
    let msg_bytes = decrypt(&sk.serialize(), &ciphertext).unwrap();
    return String::from_utf8(msg_bytes.to_vec()).unwrap();
}