use p256::{ecdsa::{SigningKey, Signature, signature::Signer, VerifyingKey, signature::Verifier}};
use rand_core::OsRng;

pub fn keyGen_Signature() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::random(&mut OsRng);
    // let sk = signing_key.to_bytes();

    let verify_key = VerifyingKey::from(&signing_key);
    // let vk = verify_key.to_encoded_point(false);

    // println!("\n- Signing key 2 (or secret key): {:x?}", hex::encode(sk));
    // println!("- Verifying key 2 (or public key): {:x?}", hex::encode(vk));
    return (signing_key, verify_key);
}

pub fn sig(signing_key: SigningKey, message: String) -> Signature {
    // println!("\nSignature: {:x?}", hex::encode(signature));
    return signing_key.sign(message.as_bytes());
}

pub fn vf(verify_key: VerifyingKey, message: String, signature: Signature) -> bool {
    return verify_key.verify(message.as_bytes(), &signature).is_ok();
}