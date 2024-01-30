use p256::{ecdsa::{Signature}, FieldBytes};
use hex::{FromHex, FromHexError};

pub fn hex_string_to_signature(hex_string: &str) -> Result<Signature, FromHexError> {
    // Convert hexadecimal string to bytes
    let signature_bytes = Vec::from_hex(hex_string).expect("");

    // Extract 'r' and 's' components directly as scalars
    let r_scalar = FieldBytes::from_slice(&signature_bytes[0..32]);
    let s_scalar = FieldBytes::from_slice(&signature_bytes[32..64]);

    // Create a Signature using the 'r' and 's' components
    let signature = Signature::from_scalars(*r_scalar, *s_scalar).expect("");

    Ok(signature)
}